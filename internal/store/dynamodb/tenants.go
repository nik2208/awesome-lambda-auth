package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// This file implements auth.TenantStore (data-model.md §1.4 #38-#46).
//
// Two item types, and one of them has been written since the first commit of
// this package: CreateUser writes a membership at PK=TENANT#<t>,
// SK=MEMBER#<u> inside its registration transaction, precisely so that a user
// can never exist without one. What was missing was the *directory* — the
// tenant records themselves — and the eight methods over the pair.
//
//	directory   PK=TENANTS      SK=TENANT#<t>   (no GSI1)
//	membership  PK=TENANT#<t>   SK=MEMBER#<u>   GSI1PK=USERID#<u>, GSI1SK=TENANT#<t>
//
// The directory is one partition, which §2.3 already argues for: GetTenantByID
// becomes a GetItem and GetAllTenants a Query on one partition, where a GSI
// would reintroduce eventual consistency and a second copy of every record. The
// membership partition is per tenant, which makes GetUsersForTenant a Query
// scoped to exactly one tenant by its key — tenant isolation for free, and §3's
// rule satisfied without a filter anywhere.
//
// The membership's GSI1 entry answers the one direction the main table cannot:
// GetTenantsForUser carries a user id and no tenant, so it has no partition to
// query. That is one of the four fan-outs §2.1 says a GSI is warranted for.
//
// # What a tenant is, and what a user's TenantID is
//
// These are two different relations and this file keeps them apart, because the
// core does. auth.User.TenantID is the tenant a user *belongs to*, part of its
// identity and of its partition key. The membership table is a many-to-many
// association a user can hold several of. AdminUserStore.ListUsers filters on
// the first and never consults the second — see its doc — so a user whose
// TenantID is "acme" and who is additionally associated with "globex" is listed
// under "acme" and nowhere else, while GetTenantsForUser reports both.

// Tenant directory attributes (data-model.md §5). The id is not duplicated into
// an attribute: it is the tail of SK, as a mail template's id is.
//
// `name` is not among them: the constant is already declared in users.go, where
// the linked-account item uses the same spelling of the same word, and the rule
// this package follows is that one attribute name is one constant — a second
// declaration of the same string is what lets a codec and a condition drift
// apart. Same argument settings.go makes for sharing attrRequire2FA with the
// user profile.
const attrTenantConfig = "config"

// attrIsActive is shared by three item types that never share an item: the
// tenant directory entry, the API key (api_keys.go) and the webhook
// subscription (webhooks.go). All three take the name from the same place — it
// is `isActive` in the reference's JSON for the two that have JSON — so it is
// one constant rather than three, for the reason above.
const attrIsActive = "isActive"

// MaxTenantBytes caps a tenant record as itemBytes accounts for it, for
// MaxTemplateBytes' reason and with its margin: Tenant.Config is a
// caller-supplied map with no bound anywhere in the interface, and a record that
// cannot be written is a tenant that cannot be created with an error nobody can
// read. Refusing at 300 KB turns the SDK's ValidationException into
// ErrTenantTooLarge before anything is written.
const MaxTenantBytes = 300 * 1024

// ErrTenantTooLarge means the tenant record exceeds MaxTenantBytes. Nothing was
// written.
var ErrTenantTooLarge = errors.New("dynamodb: tenant record exceeds the item size limit")

// Tenants returns this store as the auth.TenantStore the composition root hands
// to auth.WithTenantProvider. The methods are on *Store itself; the accessor
// exists so cmd/auth can find the capability structurally.
func (s *Store) Tenants() auth.TenantStore { return s }

// TenantStore is handed to the core by name (auth.WithTenantProvider), so a
// drifted signature fails the composition root's build rather than going quiet.
// See interfaces.go for the convention.
var _ auth.TenantStore = (*Store)(nil)

// CreateTenant writes a directory entry, refusing a duplicate id.
//
// attribute_not_exists on the *sort* key, not the partition key: every tenant
// shares the TENANTS partition, so attribute_not_exists(PK) would be false for
// the second tenant ever created. ErrAlreadyExists is what
// MemoryTenantStore answers for a duplicate, and it is preserved by a condition
// rather than by a read, so two concurrent creates of one id produce exactly one
// winner.
func (s *Store) CreateTenant(ctx context.Context, tenant auth.Tenant) (auth.Tenant, error) {
	if err := checkID("tenant id", tenant.ID); err != nil {
		return auth.Tenant{}, err
	}
	if tenant.CreatedAt.IsZero() {
		// MemoryTenantStore stores whatever it is handed, so a zero CreatedAt
		// round-trips as zero there. Stamping it here is the same bargain
		// APIKeyRecord.CreatedAt describes from the other side: a tenant with no
		// creation time is a row an admin screen shows a blank for, and nothing
		// upstream fills it in.
		tenant.CreatedAt = s.nowUTC()
	}
	it, err := tenantItem(tenant)
	if err != nil {
		return auth.Tenant{}, err
	}
	if n := itemBytes(it); n > MaxTenantBytes {
		return auth.Tenant{}, wrapSize(ErrTenantTooLarge, tenant.ID, n, MaxTenantBytes)
	}
	if _, err := s.api.PutItem(ctx, &awsddb.PutItemInput{
		TableName:                aws.String(s.table),
		Item:                     it,
		ConditionExpression:      aws.String("attribute_not_exists(#SK)"),
		ExpressionAttributeNames: exprNames(attrSK),
	}); err != nil {
		if isConditionFailed(err) {
			return auth.Tenant{}, auth.ErrAlreadyExists
		}
		return auth.Tenant{}, wrap("create tenant", err)
	}
	return tenant, nil
}

// GetTenantByID reads one directory entry, strongly consistent: an administrator
// who has just created a tenant must be able to associate a user with it in the
// next request, and AssociateUserWithTenant's own ConditionCheck would otherwise
// race an eventually-consistent replica.
func (s *Store) GetTenantByID(ctx context.Context, id string) (auth.Tenant, error) {
	if err := checkID("tenant id", id); err != nil {
		// An id the store cannot key is an id it does not hold. The typed error
		// would be a 500 where an unknown id is a 404, and ErrTenantNotFound is
		// what the caller is written to expect.
		return auth.Tenant{}, auth.ErrTenantNotFound
	}
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(tenantsPK, tenantDirSK(id)),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.Tenant{}, wrap("get tenant", err)
	}
	if len(out.Item) == 0 {
		return auth.Tenant{}, auth.ErrTenantNotFound
	}
	return tenantFromItem(out.Item)
}

// GetAllTenants lists the directory, id-ascending — the order a Query over one
// partition returns, and the order MemoryTenantStore sorts into, so the two
// agree without either being told to.
//
// Capped at Options.MaxTenants and refusing rather than truncating, which
// answers the first of the two list interfaces §8.6 left open. The number is
// chosen against the partition rather than the screen: every tenant is one item
// in one partition (§6.2), so a deployment with six figures of tenants has a hot
// partition long before it has a slow listing.
func (s *Store) GetAllTenants(ctx context.Context) ([]auth.Tenant, error) {
	items, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		KeyConditionExpression:   aws.String("#PK = :pk AND begins_with(#SK, :prefix)"),
		ExpressionAttributeNames: exprNames(attrPK, attrSK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":     avS(tenantsPK),
			":prefix": avS(pkTenantPrefix),
		},
		ConsistentRead: aws.Bool(true),
	}, s.maxTenants)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap("get all tenants", err)
	}
	out := make([]auth.Tenant, 0, len(items))
	for _, m := range items {
		t, err := tenantFromItem(m)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// UpdateTenant sets the three mutable fields, refusing a tenant that is not
// there.
//
// Name, isActive and config and nothing else, which is exactly what
// MemoryTenantStore copies across (feature_stores.go) — the id is the key and
// CreatedAt is not a caller's to move. An UpdateItem rather than a PutItem for
// the reason session rotation uses one: a Put would erase any attribute a later
// build of this package adds to the record, and a conditional Put would still
// erase one written by a concurrent writer.
//
// An empty name REMOVEs the attribute rather than writing "", which is §5's
// omission rule and round-trips identically.
func (s *Store) UpdateTenant(ctx context.Context, id string, update auth.Tenant) error {
	if err := checkID("tenant id", id); err != nil {
		return auth.ErrTenantNotFound
	}
	cfg, err := anyMapAV(update.Config)
	if err != nil {
		return err
	}

	set := []string{"#isActive = :active", "#config = :config", "#updatedAt = :now"}
	remove := []string{}
	values := map[string]types.AttributeValue{
		":active": &types.AttributeValueMemberBOOL{Value: update.IsActive},
		":config": cfg,
		":now":    avS(formatTime(s.nowUTC())),
	}
	if update.Name == "" {
		remove = append(remove, "#name")
	} else {
		set = append(set, "#name = :name")
		values[":name"] = avS(update.Name)
	}

	if _, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       key(tenantsPK, tenantDirSK(id)),
		UpdateExpression:          aws.String(updateExpression(set, remove)),
		ConditionExpression:       aws.String("attribute_exists(#SK)"),
		ExpressionAttributeNames:  exprNames(attrSK, attrName, attrIsActive, attrTenantConfig, attrUpdatedAt),
		ExpressionAttributeValues: values,
	}); err != nil {
		if isConditionFailed(err) {
			return auth.ErrTenantNotFound
		}
		return wrap("update tenant", err)
	}
	return nil
}

// DeleteTenant removes the directory entry and every membership of the tenant.
//
// Not the users. A tenant's members are users whose own records live under
// USER#<t>#<u> and whose TenantID is part of their identity; deleting them here
// would turn an administrative tidy-up into an irreversible account deletion,
// and MemoryTenantStore deletes only its two index maps. What is left behind is
// a user whose TenantID names a tenant that no longer exists, which is the same
// state the reference leaves and which ListUsers still reports.
//
// An unknown tenant is not an error, matching the memory store's unconditional
// deletes, and the sweep is idempotent on retry for the reason DeleteUser's is.
func (s *Store) DeleteTenant(ctx context.Context, id string) error {
	if err := checkID("tenant id", id); err != nil {
		return nil
	}
	members, err := s.membershipItems(ctx, id)
	if err != nil {
		return err
	}
	keys := make([]map[string]types.AttributeValue, 0, len(members)+1)
	keys = append(keys, key(tenantsPK, tenantDirSK(id)))
	for _, m := range members {
		keys = append(keys, key(getS(m, attrPK), getS(m, attrSK)))
	}
	if err := s.deleteKeys(ctx, keys); err != nil {
		return wrap("delete tenant", err)
	}
	return nil
}

// AssociateUserWithTenant records a membership, refusing one for a tenant that
// does not exist.
//
// A transaction for AddRoleToUser's reason: MemoryTenantStore answers
// ErrTenantNotFound for an unknown tenant, and preserving that means checking
// the directory entry and writing the membership with no gap between them.
//
// The membership itself is unconditional, so re-associating is a no-op — which
// also means this method and CreateUser can write the same item without either
// having to know about the other.
func (s *Store) AssociateUserWithTenant(ctx context.Context, userID, tenantID string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}
	err := s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{ConditionCheck: &types.ConditionCheck{
				TableName:                aws.String(s.table),
				Key:                      key(tenantsPK, tenantDirSK(tenantID)),
				ConditionExpression:      aws.String("attribute_exists(#SK)"),
				ExpressionAttributeNames: exprNames(attrSK),
			}},
			{Put: &types.Put{
				TableName: aws.String(s.table),
				Item:      s.membershipItem(userID, tenantID),
			}},
		},
	})
	if err != nil {
		if reasons, ok := txConditionFailures(err); ok {
			if _, failed := txFailedAt(reasons, 0); failed {
				return auth.ErrTenantNotFound
			}
		}
		return wrap("associate user with tenant", err)
	}
	return nil
}

// DisassociateUserFromTenant drops a membership. Unconditional and never an
// error for one that is not there, matching MemoryTenantStore.
//
// Note what it does not do: it leaves auth.User.TenantID alone. The two
// relations are separate (see the file header), and a user cannot be made
// tenant-less by an association being removed — nor could it be, since the
// tenant is part of the user's partition key.
func (s *Store) DisassociateUserFromTenant(ctx context.Context, userID, tenantID string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}
	if _, err := s.api.DeleteItem(ctx, &awsddb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key:       key(tenantPK(tenantID), memberSK(userID)),
	}); err != nil {
		return wrap("disassociate user from tenant", err)
	}
	return nil
}

// GetTenantsForUser resolves a user's memberships through GSI1 and then reads
// the directory entries they name.
//
// This is the fan-out the index exists for: the method carries a user id and no
// tenant, so the main table has no partition to query. It is eventually
// consistent, which is acceptable here for the reason it is in
// ListSessionsForUser — this is an account screen and a `/me` bundle, not an
// authorisation decision.
//
// A membership naming a tenant that has been deleted is dropped rather than
// reported as a zero Tenant, which is what MemoryTenantStore does too: it looks
// each id up in byID and skips a miss.
//
// Ordering is id-ascending. GSI1SK is TENANT#<t>, so the index already returns
// them that way and BatchGetItem's reordering is undone by resolveIndexEntries;
// MemoryTenantStore sorts on Tenant.ID, so the two agree.
func (s *Store) GetTenantsForUser(ctx context.Context, userID string) ([]auth.Tenant, error) {
	if err := checkID("user id", userID); err != nil {
		return nil, err
	}
	entries, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		IndexName:                aws.String(s.index),
		KeyConditionExpression:   aws.String("#GSI1PK = :owner AND begins_with(#GSI1SK, :prefix)"),
		ExpressionAttributeNames: exprNames(attrGSI1PK, attrGSI1SK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":owner":  avS(gsi1UserID(userID)),
			":prefix": avS(pkTenantPrefix),
		},
	}, s.maxTenants)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap("query tenants for user", err)
	}
	if len(entries) == 0 {
		return []auth.Tenant{}, nil
	}

	// The directory key comes out of the index entry's GSI1SK, which already is
	// the TENANT#<t> string tenantDirSK builds — not out of the entry's base PK,
	// though that happens to carry the same value. Taking it from the sort key is
	// what keeps this readable as "the tenant this membership names".
	items, err := s.resolveIndexEntries(ctx, entries, func(e map[string]types.AttributeValue) map[string]types.AttributeValue {
		return key(tenantsPK, getS(e, attrGSI1SK))
	})
	if err != nil {
		return nil, wrap("get tenants for user", err)
	}
	out := make([]auth.Tenant, 0, len(items))
	for _, m := range items {
		t, err := tenantFromItem(m)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// GetUsersForTenant lists a tenant's members, id-ascending.
//
// A Query on PK=TENANT#<t>, so the tenant scope is the key and no other tenant's
// partition is reachable from it (§3). The order is the SK's, which is the user
// id's, matching MemoryTenantStore's sort.
//
// Capped at Options.MaxUsersPerTenant and refusing rather than truncating, which
// answers the second of §8.6's two open list interfaces. Ten thousand rather
// than the thousand GetAllTenants gets, because this one is genuinely a
// membership list: a tenant with ten thousand members is a customer, where a
// deployment with ten thousand tenants is a different kind of event.
func (s *Store) GetUsersForTenant(ctx context.Context, tenantID string) ([]string, error) {
	items, err := s.membershipItems(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(items))
	for _, m := range items {
		id, ok := strings.CutPrefix(getS(m, attrSK), skMemberPrefix)
		if !ok {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}

// membershipItems drains one tenant's MEMBER# range. Shared by
// GetUsersForTenant and DeleteTenant so the two cannot disagree about what a
// membership is.
func (s *Store) membershipItems(ctx context.Context, tenantID string) ([]map[string]types.AttributeValue, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return nil, err
	}
	items, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		KeyConditionExpression:   aws.String("#PK = :pk AND begins_with(#SK, :prefix)"),
		ExpressionAttributeNames: exprNames(attrPK, attrSK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":     avS(tenantPK(tenantID)),
			":prefix": avS(skMemberPrefix),
		},
		ConsistentRead: aws.Bool(true),
	}, s.maxUsersPerTenant)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap("query tenant memberships", err)
	}
	return items, nil
}

// membershipItem is the association CreateUser also writes, in one place so the
// two writers cannot produce different shapes.
func (s *Store) membershipItem(userID, tenantID string) item {
	return item{}.
		sAlways(attrPK, tenantPK(tenantID)).
		sAlways(attrSK, memberSK(userID)).
		stamp(typeMember).
		sAlways(attrUserID, userID).
		sAlways(attrTenantID, tenantID).
		sAlways(attrGSI1PK, gsi1UserID(userID)).
		sAlways(attrGSI1SK, tenantPK(tenantID)).
		t(attrCreatedAt, s.nowUTC())
}

// tenantItem encodes a directory entry (data-model.md §5, "Tenant"). isActive is
// written even when false — it is a flag whose absence would be indistinguishable
// from a tenant nobody activated — while the name follows the omission rule.
func tenantItem(t auth.Tenant) (item, error) {
	cfg, err := anyMapAV(t.Config)
	if err != nil {
		return nil, err
	}
	return item{}.
		sAlways(attrPK, tenantsPK).
		sAlways(attrSK, tenantDirSK(t.ID)).
		stamp(typeTenant).
		s(attrName, t.Name).
		b(attrIsActive, t.IsActive).
		av(attrTenantConfig, cfg).
		t(attrCreatedAt, t.CreatedAt), nil
}

func tenantFromItem(m map[string]types.AttributeValue) (auth.Tenant, error) {
	if err := checkVersion(m, typeTenant); err != nil {
		return auth.Tenant{}, err
	}
	id, ok := strings.CutPrefix(getS(m, attrSK), pkTenantPrefix)
	if !ok {
		return auth.Tenant{}, fmt.Errorf("dynamodb: %q is not a tenant sort key", getS(m, attrSK))
	}
	createdAt, err := getTime(m, attrCreatedAt)
	if err != nil {
		return auth.Tenant{}, err
	}
	return auth.Tenant{
		ID:        id,
		Name:      getS(m, attrName),
		IsActive:  getBool(m, attrIsActive),
		Config:    anyMapFromAV(m[attrTenantConfig]),
		CreatedAt: createdAt,
	}, nil
}

// wrapSize is the message shape the three size caps share, so an operator sees
// the same sentence whichever limit they hit.
func wrapSize(sentinel error, name string, got, limit int) error {
	return fmt.Errorf("%w: %q would be %d bytes, limit %d", sentinel, name, got, limit)
}
