package dynamodb

import (
	"context"
	"errors"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// This file implements auth.RolesPermissionsStore and auth.RoleLister: the RBAC
// half of the admin surface (data-model.md §1.4 #29-#37, #47c).
//
// Two item types, not one, and the split is the reference's rather than a
// choice made here. A role *definition* is deployment-global — CreateRole takes
// (role, permissions) and no tenant — while an *assignment* is tenant-scoped:
// AddRoleToUser takes (userID, role, tenantID). Folding them into one item type
// would mean either inventing a tenant for the definition or dropping the
// tenant from the assignment, and the second would let a role granted in one
// tenant authorise in another.
//
//	definition  PK=ROLES               SK=ROLE#<role>
//	assignment  PK=USER#<t>#<u>        SK=ROLE#<role>   GSI1PK=ROLE#<role>
//
// The definition's partition is a directory, and that is a correction to §1.4:
// the row keyed it at PK=ROLE#<role>, one partition per role, which serves every
// method that names a role and cannot serve the one that does not.
// RoleLister.GetAllRoles (core v0.8.0) enumerates the set, and a per-role
// partition can only be enumerated by a table Scan. §2.3 already makes this
// argument for the tenant directory against a set with the same shape — bounded,
// administrator-authored, rarely written — so the same answer applies.
//
// # Permissions are a String Set, and that is what makes two methods read-free
//
// AddPermissionToRole and RemovePermissionFromRole are an `ADD` and a `DELETE`
// on an SS attribute: atomic, no read, and idempotent, which is exactly the
// semantics MemoryRolesPermissionsStore gets from a Go map under a lock. An `L`
// of `S` would have to be read, searched and written back, and two concurrent
// grants would lose one.
//
// DynamoDB forbids an empty set, so a role with no permissions carries no
// `permissions` attribute at all and GetPermissionsForRole answers an empty
// slice — which is also what happens when `DELETE` removes the last member, so
// the two states are one state and nothing has to reconcile them. §5 already
// stated this rule; it is load-bearing here.

// attrPermissions is the role definition's permission set.
const attrPermissions = "permissions"

// roleDirectoryCap bounds GetAllRoles, whose interface has no cursor at all —
// not even limit/offset, matching the reference, because "the roles of a
// deployment are a bounded, human-authored set" and the route pairs each name
// with its permissions in a fan-out it makes no attempt to page.
//
// A thousand is an integrity check rather than a page size, exactly as
// templateDirectoryCap is: four digits of roles means something is writing them
// that should not be, and the honest answer to that is ErrResultTooLarge rather
// than a listing that silently stops.
const roleDirectoryCap = 1000

// maxRolesPerUser bounds GetRolesForUser and, with it, GetPermissionsForUser and
// UserHasPermission — all three walk one user's ROLE# range. A hundred roles on
// one user is not an authorisation model, and the Query lives in the user's own
// item collection, whose whole discipline is that it stays small (§2.2).
const maxRolesPerUser = 100

// Roles returns this store as the auth.RolesPermissionsStore the composition
// root hands to auth.WithRBACProvider, and it is also the auth.RoleLister the
// core type-asserts that value to (Service.ListAllRoles). The methods are on
// *Store itself; the accessor exists so cmd/auth can find the capability
// structurally, the way it finds Templates() and Settings().
func (s *Store) Roles() auth.RolesPermissionsStore { return s }

// RolesPermissionsStore is handed to the core by name (auth.WithRBACProvider),
// so a drift in its ten signatures fails the composition root's build.
// RoleLister is not: the core reaches it by asserting the *configured* RBAC
// store, so a drift there is M8's GET /admin/api/roles answering the reference's
// 501 from a binary that built cleanly. See interfaces.go for the convention.
var (
	_ auth.RolesPermissionsStore = (*Store)(nil)
	_ auth.RoleLister            = (*Store)(nil)
)

// CreateRole writes a role definition, replacing any existing one.
//
// Unconditional, because MemoryRolesPermissionsStore is: it assigns a fresh
// permission set over whatever was there (feature_stores.go). So creating a role
// that exists is a reset of its permissions and not an error, and no
// ErrAlreadyExists is invented for a case the reference does not have.
//
// An empty permission list creates a role with no permissions rather than no
// role. That is the case RoleLister's doc calls out explicitly — "Roles with no
// permissions are still roles and are still listed; CreateRole with an empty
// permission list creates one" — and it works here because the item exists
// whether or not the SS attribute does.
func (s *Store) CreateRole(ctx context.Context, role string, permissions []string) error {
	if err := checkOpaque("role name", role, maxRoleNameLen); err != nil {
		return err
	}
	if _, err := s.api.PutItem(ctx, &awsddb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      roleItem(role, permissions),
	}); err != nil {
		return wrap("create role", err)
	}
	return nil
}

// DeleteRole removes the definition and every assignment of it.
//
// The assignments are found through GSI1, which is eventually consistent, so an
// assignment written microseconds earlier can be missed — the same trade
// DeleteUser's session sweep makes, and harmless for a similar reason: a
// surviving assignment names a definition that no longer exists, so
// GetPermissionsForRole answers nothing for it and GetPermissionsForUser
// contributes nothing from it. It is a row that grants no authority, not a
// dangling grant. GetRolesForUser would still list the name, which is the whole
// of the visible residue.
//
// An unknown role is not an error. MemoryRolesPermissionsStore deletes from its
// maps unconditionally, so a second DeleteRole succeeds; the sweep is idempotent
// for the same reason DeleteUser's is — a delete of an absent item succeeds.
func (s *Store) DeleteRole(ctx context.Context, role string) error {
	if err := checkOpaque("role name", role, maxRoleNameLen); err != nil {
		return err
	}
	assignments, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		IndexName:                aws.String(s.index),
		KeyConditionExpression:   aws.String("#GSI1PK = :role"),
		ExpressionAttributeNames: exprNames(attrGSI1PK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":role": avS(gsi1Role(role)),
		},
	}, s.maxUsersPerTenant)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			// §8.8's open question in its concrete form: a role assigned to more
			// users than one synchronous call can sweep. Refusing is the only
			// honest answer a blocking interface allows — the alternative is a
			// Lambda that times out having deleted an arbitrary prefix of the
			// assignments, which is worse than having deleted none.
			return err
		}
		return wrap("query role assignments", err)
	}

	// The definition last would leave a window in which the role is
	// unassignable but still listed; the definition first leaves one in which it
	// is listed by GetRolesForUser and grants nothing. The second is the safe
	// direction, so the definition goes first.
	keys := make([]map[string]types.AttributeValue, 0, len(assignments)+1)
	keys = append(keys, key(rolesPK, roleSK(role)))
	for _, m := range assignments {
		// The assignment's own key, taken from the index entry. That is
		// reachability rather than ownership (§5): the sort key carries the role
		// name, so this key can only ever name an assignment *of this role*, and
		// a stale entry names one that is already gone — which a delete answers
		// with success.
		keys = append(keys, key(getS(m, attrPK), getS(m, attrSK)))
	}
	if err := s.deleteKeys(ctx, keys); err != nil {
		return wrap("delete role", err)
	}
	return nil
}

// AddPermissionToRole grants one permission, atomically and with no read.
//
// It creates the role if it does not exist, which is MemoryRolesPermissionsStore's
// behaviour (`if s.rolePermissions[role] == nil` it makes one) and the reason
// the update writes `_t` and `_v` alongside the `ADD`: an item DynamoDB creates
// for an update would otherwise carry only its key and the set, and a migration
// sweep driven off `_t` would not see it.
func (s *Store) AddPermissionToRole(ctx context.Context, role, permission string) error {
	return s.changeRolePermission(ctx, role, permission, true)
}

// RemovePermissionFromRole revokes one permission.
//
// Conditional on the role existing, and a lost condition is success. The
// condition is not about correctness of the revocation — a `DELETE` of a member
// that is not there is already a no-op — but about not *creating* the role: an
// UpdateItem whose only action is a DELETE still brings the item into existence
// with its key, so revoking a permission from a role nobody defined would
// define it. MemoryRolesPermissionsStore deletes from a nil map and creates
// nothing.
func (s *Store) RemovePermissionFromRole(ctx context.Context, role, permission string) error {
	return s.changeRolePermission(ctx, role, permission, false)
}

func (s *Store) changeRolePermission(ctx context.Context, role, permission string, grant bool) error {
	if err := checkOpaque("role name", role, maxRoleNameLen); err != nil {
		return err
	}
	if permission == "" {
		// DynamoDB cannot hold an empty string in a String Set, and nothing in
		// the core or the reference produces or resolves an empty permission, so
		// this is refused at the boundary rather than failing inside the SDK.
		return errors.New("dynamodb: permission is required")
	}

	in := &awsddb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key:       key(rolesPK, roleSK(role)),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":p": &types.AttributeValueMemberSS{Value: []string{permission}},
		},
	}
	if grant {
		in.UpdateExpression = aws.String("SET #_t = :t, #_v = :v ADD #permissions :p")
		in.ExpressionAttributeNames = exprNames(attrType, attrVer, attrPermissions)
		in.ExpressionAttributeValues[":t"] = avS(typeRole)
		in.ExpressionAttributeValues[":v"] = avN(schemaVersion)
	} else {
		in.UpdateExpression = aws.String("DELETE #permissions :p")
		in.ConditionExpression = aws.String("attribute_exists(#SK)")
		in.ExpressionAttributeNames = exprNames(attrSK, attrPermissions)
	}

	if _, err := s.api.UpdateItem(ctx, in); err != nil {
		if !grant && isConditionFailed(err) {
			return nil
		}
		return wrap("change role permission", err)
	}
	return nil
}

// GetPermissionsForRole reads one definition's permissions, sorted.
//
// Strongly consistent: an administrator who has just granted a permission must
// see it on the next read of the screen they granted it from, and the set is one
// item so the read costs nothing extra.
//
// A role that does not exist answers an empty slice and no error, which is what
// MemoryRolesPermissionsStore does — it ranges over a nil map — and what the
// admin roles route needs, since it fans out over GetAllRoles and would
// otherwise fail the whole listing on a role deleted mid-fan-out.
func (s *Store) GetPermissionsForRole(ctx context.Context, role string) ([]string, error) {
	if err := checkOpaque("role name", role, maxRoleNameLen); err != nil {
		return nil, err
	}
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(rolesPK, roleSK(role)),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, wrap("get permissions for role", err)
	}
	if len(out.Item) == 0 {
		return []string{}, nil
	}
	if err := checkVersion(out.Item, typeRole); err != nil {
		return nil, err
	}
	return sortedSS(out.Item, attrPermissions), nil
}

// GetAllRoles implements auth.RoleLister: every role CreateRole has defined,
// name-ascending.
//
// The set is the definitions, not the roles users happen to hold. A role created
// and assigned to nobody is still a role — GET /admin/api/roles exists to show
// exactly that — and a role with no permissions is too.
//
// The order is what a Query over the ROLES partition returns, which is SK
// ascending, which is the role name ascending because the name is the SK's tail.
// That is the core's normative order exactly, so there is nothing to register:
// the directory partition was chosen for the Query and gets the order for free.
func (s *Store) GetAllRoles(ctx context.Context) ([]string, error) {
	items, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                 aws.String(s.table),
		KeyConditionExpression:    aws.String("#PK = :pk"),
		ExpressionAttributeNames:  exprNames(attrPK),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(rolesPK)},
		ConsistentRead:            aws.Bool(true),
	}, roleDirectoryCap)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap("get all roles", err)
	}
	out := make([]string, 0, len(items))
	for _, m := range items {
		role, ok := roleFromSK(getS(m, attrSK))
		if !ok {
			continue
		}
		out = append(out, role)
	}
	return out, nil
}

// AddRoleToUser assigns a role to a user within one tenant.
//
// A transaction, for one reason: the reference answers ErrRoleNotFound for a
// role that was never defined (feature_stores.go), and preserving that means
// checking the definition and writing the assignment without a gap in which the
// definition could be deleted. A ConditionCheck on the directory entry is what
// makes the check part of the write rather than a read before it.
//
// The assignment itself is unconditional: re-assigning a role a user already
// holds is a no-op there and is one here.
func (s *Store) AddRoleToUser(ctx context.Context, userID, role string, tenantID string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}
	if err := checkOpaque("role name", role, maxRoleNameLen); err != nil {
		return err
	}

	err := s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{ConditionCheck: &types.ConditionCheck{
				TableName:                aws.String(s.table),
				Key:                      key(rolesPK, roleSK(role)),
				ConditionExpression:      aws.String("attribute_exists(#SK)"),
				ExpressionAttributeNames: exprNames(attrSK),
			}},
			{Put: &types.Put{
				TableName: aws.String(s.table),
				Item:      s.roleAssignmentItem(userID, tenantID, role),
			}},
		},
	})
	if err != nil {
		if reasons, ok := txConditionFailures(err); ok {
			if _, failed := txFailedAt(reasons, 0); failed {
				return auth.ErrRoleNotFound
			}
		}
		return wrap("add role to user", err)
	}
	return nil
}

// RemoveRoleFromUser drops one assignment.
//
// Unconditional and never an error for an assignment that is not there:
// MemoryRolesPermissionsStore deletes from a possibly-nil map and reports
// nothing, and the admin route awaits it without a lookup of its own.
func (s *Store) RemoveRoleFromUser(ctx context.Context, userID, role string, tenantID string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}
	if err := checkOpaque("role name", role, maxRoleNameLen); err != nil {
		return err
	}
	if _, err := s.api.DeleteItem(ctx, &awsddb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key:       key(userPK(tenantID, userID), roleSK(role)),
	}); err != nil {
		return wrap("remove role from user", err)
	}
	return nil
}

// GetRolesForUser lists one user's roles in one tenant, name-ascending.
//
// A Query over the user's own item collection, so it is strongly consistent and
// tenant-isolated by the key rather than by a filter (§3): a user's assignments
// in another tenant live in another partition and are not reachable from here.
// The order is the SK's, which is the role name's, matching the memory store's
// sort.
func (s *Store) GetRolesForUser(ctx context.Context, userID, tenantID string) ([]string, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return nil, err
	}
	if err := checkID("user id", userID); err != nil {
		return nil, err
	}
	items, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		KeyConditionExpression:   aws.String("#PK = :pk AND begins_with(#SK, :prefix)"),
		ExpressionAttributeNames: exprNames(attrPK, attrSK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":     avS(userPK(tenantID, userID)),
			":prefix": avS(skRolePrefix),
		},
		ConsistentRead: aws.Bool(true),
	}, maxRolesPerUser)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap("get roles for user", err)
	}
	out := make([]string, 0, len(items))
	for _, m := range items {
		role, ok := roleFromSK(getS(m, attrSK))
		if !ok {
			continue
		}
		out = append(out, role)
	}
	return out, nil
}

// GetPermissionsForUser is the union of the permissions of the user's roles,
// deduplicated and sorted — MemoryRolesPermissionsStore's composition, with the
// per-role reads batched into one BatchGetItem instead of R GetItems.
//
// A role the user holds whose definition has been deleted contributes nothing
// and is not an error, which is what makes DeleteRole's eventually-consistent
// sweep harmless.
func (s *Store) GetPermissionsForUser(ctx context.Context, userID, tenantID string) ([]string, error) {
	roles, err := s.GetRolesForUser(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return []string{}, nil
	}
	keys := make([]map[string]types.AttributeValue, 0, len(roles))
	for _, role := range roles {
		keys = append(keys, key(rolesPK, roleSK(role)))
	}
	items, err := s.batchGet(ctx, keys)
	if err != nil {
		return nil, wrap("get permissions for user", err)
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(items)*2)
	for _, m := range items {
		if err := checkVersion(m, typeRole); err != nil {
			return nil, err
		}
		for _, p := range sortedSS(m, attrPermissions) {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}

// UserHasPermission is GetPermissionsForUser plus a membership test, which is
// what the memory store does.
//
// Not a cheaper query, deliberately. The obvious optimisation — resolve the
// user's roles, then GetItem each definition until one matches — is only cheaper
// when the answer is yes and the first role happens to carry it, and is the same
// cost when the answer is no, which is the answer a guard returns on every
// request it refuses. Composing the two keeps one code path for both and keeps
// this method's answer identical to the listing the same caller can ask for.
func (s *Store) UserHasPermission(ctx context.Context, userID, permission, tenantID string) (bool, error) {
	permissions, err := s.GetPermissionsForUser(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	return slices.Contains(permissions, permission), nil
}

// roleItem encodes a definition (data-model.md §5, "Role definition"). The role
// name is not duplicated into an attribute: it is the tail of SK and roleFromSK
// is the only decoder, exactly as a mail template's id is.
//
// An empty permission list omits the attribute, because DynamoDB forbids an
// empty String Set. Duplicates in the input collapse, which is the set semantics
// the reference has too — its permissions live in a Set there and a map here.
func roleItem(role string, permissions []string) item {
	it := item{}.
		sAlways(attrPK, rolesPK).
		sAlways(attrSK, roleSK(role)).
		stamp(typeRole)
	if unique := dedupe(permissions); len(unique) > 0 {
		it = it.av(attrPermissions, &types.AttributeValueMemberSS{Value: unique})
	}
	return it
}

// roleAssignmentItem encodes one user's hold on one role in one tenant. It
// carries the owner in GSI1PK so DeleteRole can find it, and nothing else: the
// user id and tenant are already the main-table partition key, and §5's rule is
// that the index is never the authority on ownership.
func (s *Store) roleAssignmentItem(userID, tenantID, role string) item {
	return item{}.
		sAlways(attrPK, userPK(tenantID, userID)).
		sAlways(attrSK, roleSK(role)).
		stamp(typeRoleAssignment).
		sAlways(attrGSI1PK, gsi1Role(role)).
		sAlways(attrGSI1SK, userPK(tenantID, userID)).
		t(attrCreatedAt, s.nowUTC())
}

// sortedSS reads a String Set and sorts it. DynamoDB sets are unordered, and
// every method here answers in a documented order, so the sort is the contract
// rather than tidiness.
func sortedSS(m map[string]types.AttributeValue, name string) []string {
	av, ok := m[name].(*types.AttributeValueMemberSS)
	if !ok {
		return []string{}
	}
	out := append([]string(nil), av.Value...)
	slices.Sort(out)
	return out
}

// dedupe removes repeats and the empty string, keeping first-seen order. The
// empty string is dropped rather than refused because CreateRole's list is
// whatever the admin screen sent and one stray blank should not fail the create;
// AddPermissionToRole, where the permission *is* the request, refuses it.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
