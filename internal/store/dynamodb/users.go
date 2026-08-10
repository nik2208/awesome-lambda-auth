package dynamodb

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// Profile attributes. The four single-use families are all listed even though
// only "reset" has methods in the P1 subset: the profile item must round-trip a
// whole auth.User, so leaving the others out of the codec would silently drop
// them the first time a P2 store wrote one.
const (
	attrUserID        = "userId"
	attrTenantID      = "tenantId"
	attrEmail         = "email"
	attrPasswordHash  = "passwordHash"
	attrPhoneNumber   = "phoneNumber"
	attrFirstName     = "firstName"
	attrLastName      = "lastName"
	attrRole          = "role"
	attrEmailVerified = "isEmailVerified"
	attrRequire2FA    = "require2FA"
	attrTOTPEnabled   = "isTotpEnabled"
	attrTOTPSecret    = "totpSecret"
	attrPendingEmail  = "pendingEmail"
	attrCreatedAt     = "createdAt"
	attrUpdatedAt     = "updatedAt"

	// OAuth linked-account and pending-link attributes. They live on their own
	// item types, not on the profile, but the names belong in one place with the
	// rest so a codec and a condition cannot disagree about one.
	attrLinkID        = "linkId"
	attrProvider      = "provider"
	attrProviderID    = "providerId"
	attrName          = "name"
	attrPicture       = "picture"
	attrRedirectURL   = "redirectUrl"
	attrMetaExpiresAt = "metaExpiresAt"

	attrMagicHash  = "magicHash"
	attrMagicExp   = "magicExp"
	attrVerifyHash = "verifyHash"
	attrVerifyExp  = "verifyExp"
	attrEchgHash   = "echgHash"
	attrEchgExp    = "echgExp"
	attrSMSHash    = "smsHash"
	attrSMSExp     = "smsExp"
)

// maxUserCollectionItems caps the unconditioned Query over USER#<t>#<u>. The
// collection is bounded by design — only META#, PROFILE and ROLE# live there —
// so this is a tripwire for a future child type that broke that rule, not a
// paging limit anyone should hit.
const maxUserCollectionItems = 2000

// profileItem encodes a whole auth.User. Optional values are omitted rather than
// written as NULL, which is what keeps attribute_not_exists usable as a
// condition (§5).
func profileItem(u auth.User) item {
	it := item{}.
		sAlways(attrPK, userPK(u.TenantID, u.ID)).
		sAlways(attrSK, skProfile).
		stamp(typeUser).
		sAlways(attrUserID, u.ID).
		sAlways(attrTenantID, u.TenantID).
		sAlways(attrEmail, u.Email).
		s(attrPasswordHash, u.PasswordHash).
		s(attrPhoneNumber, u.PhoneNumber).
		s(attrFirstName, u.FirstName).
		s(attrLastName, u.LastName).
		s(attrRole, u.Role).
		b(attrEmailVerified, u.IsEmailVerified).
		b(attrRequire2FA, u.Require2FA).
		b(attrTOTPEnabled, u.IsTOTPEnabled).
		s(attrTOTPSecret, u.TOTPSecret).
		s(attrPendingEmail, u.PendingEmail).
		t(attrCreatedAt, u.CreatedAt).
		t(attrUpdatedAt, u.UpdatedAt)

	// Addressed through the families rather than the bare constants, so the codec
	// and the conditional writes can never disagree about an attribute name.
	it.s(familyReset.hashAttr, u.ResetTokenHash).tp(familyReset.expAttr, u.ResetTokenExpiresAt)
	it.s(familyMagic.hashAttr, u.MagicLinkTokenHash).tp(familyMagic.expAttr, u.MagicLinkTokenExpiresAt)
	it.s(familyVerify.hashAttr, u.EmailVerificationTokenHash).tp(familyVerify.expAttr, u.EmailVerificationTokenExpiry)
	it.s(familyEchg.hashAttr, u.EmailChangeTokenHash).tp(familyEchg.expAttr, u.EmailChangeTokenExpiry)
	it.s(familySMS.hashAttr, u.SMSCodeHash).tp(familySMS.expAttr, u.SMSCodeExpiresAt)
	return it
}

// userFromItem is the inverse. Metadata, Roles, Permissions and Tenants stay nil:
// they live in other item types and the core fills them in through the optional
// stores, so inventing empty values here would hide a missing store.
func userFromItem(m map[string]types.AttributeValue) (auth.User, error) {
	if err := checkVersion(m, typeUser); err != nil {
		return auth.User{}, err
	}
	u := auth.User{
		ID:              getS(m, attrUserID),
		Email:           getS(m, attrEmail),
		PasswordHash:    getS(m, attrPasswordHash),
		TenantID:        getS(m, attrTenantID),
		PhoneNumber:     getS(m, attrPhoneNumber),
		FirstName:       getS(m, attrFirstName),
		LastName:        getS(m, attrLastName),
		Role:            getS(m, attrRole),
		IsEmailVerified: getBool(m, attrEmailVerified),
		Require2FA:      getBool(m, attrRequire2FA),
		IsTOTPEnabled:   getBool(m, attrTOTPEnabled),
		TOTPSecret:      getS(m, attrTOTPSecret),
		PendingEmail:    getS(m, attrPendingEmail),

		ResetTokenHash:             getS(m, familyReset.hashAttr),
		MagicLinkTokenHash:         getS(m, familyMagic.hashAttr),
		EmailVerificationTokenHash: getS(m, familyVerify.hashAttr),
		EmailChangeTokenHash:       getS(m, familyEchg.hashAttr),
		SMSCodeHash:                getS(m, familySMS.hashAttr),
	}

	var err error
	if u.CreatedAt, err = getTime(m, attrCreatedAt); err != nil {
		return auth.User{}, err
	}
	if u.UpdatedAt, err = getTime(m, attrUpdatedAt); err != nil {
		return auth.User{}, err
	}
	for _, f := range []struct {
		attr string
		dst  **time.Time
	}{
		{familyReset.expAttr, &u.ResetTokenExpiresAt},
		{familyMagic.expAttr, &u.MagicLinkTokenExpiresAt},
		{familyVerify.expAttr, &u.EmailVerificationTokenExpiry},
		{familyEchg.expAttr, &u.EmailChangeTokenExpiry},
		{familySMS.expAttr, &u.SMSCodeExpiresAt},
	} {
		if *f.dst, err = getTimePtr(m, f.attr); err != nil {
			return auth.User{}, err
		}
	}
	return u, nil
}

// CreateUser writes the profile, the email-uniqueness item and the tenant
// membership in one transaction (data-model.md #1).
//
// The uniqueness constraint is the reason this is a transaction and not three
// writes: a GSI cannot enforce uniqueness and is eventually consistent, so the
// only way two concurrent registrations of one address can be made to produce
// exactly one winner is a separate item guarded by attribute_not_exists inside a
// transaction. The loser gets ErrUserExists, matching memory_store.go:39-45.
func (s *Store) CreateUser(ctx context.Context, user auth.User) (auth.User, error) {
	if err := s.checkTenant(user.TenantID); err != nil {
		return auth.User{}, err
	}
	if err := checkID("user id", user.ID); err != nil {
		return auth.User{}, err
	}
	user.Email = normalizeEmail(user.Email)
	if err := checkEmail(user.Email); err != nil {
		return auth.User{}, err
	}

	notExists := "attribute_not_exists(#PK)"
	names := exprNames(attrPK)
	now := s.nowUTC()

	emailIt := item{}.
		sAlways(attrPK, emailPK(user.TenantID, user.Email)).
		sAlways(attrSK, skEmail).
		stamp(typeEmail).
		sAlways(attrUserID, user.ID).
		sAlways(attrTenantID, user.TenantID)

	// The membership item is what makes GetTenantsForUser and GetUsersForTenant
	// possible without a scan. It is written here, in the same transaction, so a
	// user can never exist without one.
	memberIt := item{}.
		sAlways(attrPK, tenantPK(user.TenantID)).
		sAlways(attrSK, memberSK(user.ID)).
		stamp(typeMember).
		sAlways(attrUserID, user.ID).
		sAlways(attrTenantID, user.TenantID).
		sAlways(attrGSI1PK, gsi1UserID(user.ID)).
		sAlways(attrGSI1SK, tenantPK(user.TenantID)).
		t(attrCreatedAt, now)

	err := s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName:                aws.String(s.table),
				Item:                     profileItem(user),
				ConditionExpression:      aws.String(notExists),
				ExpressionAttributeNames: names,
			}},
			{Put: &types.Put{
				TableName:                aws.String(s.table),
				Item:                     emailIt,
				ConditionExpression:      aws.String(notExists),
				ExpressionAttributeNames: names,
			}},
			// Unconditional: re-registering the same membership is a no-op, and
			// a stale membership must not fail a registration.
			{Put: &types.Put{TableName: aws.String(s.table), Item: memberIt}},
		},
	})
	if err != nil {
		if reasons, ok := txConditionFailures(err); ok {
			// Either the id or the address was taken. The reference returns the
			// same error for both (memory_store.go:39-45), so no distinction is
			// invented here.
			if _, failed := txFailedAt(reasons, 0); failed {
				return auth.User{}, auth.ErrUserExists
			}
			if _, failed := txFailedAt(reasons, 1); failed {
				return auth.User{}, auth.ErrUserExists
			}
		}
		return auth.User{}, wrap("create user", err)
	}
	return user, nil
}

// GetUserByEmail resolves the uniqueness item and then the profile. Two
// strongly-consistent GetItems, not one eventually-consistent index query: this
// is the login path, and a stale read here is a failed login (§2.3).
func (s *Store) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return auth.User{}, err
	}
	email = normalizeEmail(email)
	if err := checkEmail(email); err != nil {
		return auth.User{}, err
	}
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(emailPK(tenantID, email), skEmail),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.User{}, wrap("get email pointer", err)
	}
	if len(out.Item) == 0 {
		return auth.User{}, ErrUserNotFound
	}
	if err := checkVersion(out.Item, typeEmail); err != nil {
		return auth.User{}, err
	}
	return s.GetUserByID(ctx, getS(out.Item, attrUserID), tenantID)
}

// GetUserByID reads the profile straight out of USER#<t>#<u>. There is no
// tenant comparison after the read because there cannot be one: a mismatched
// tenant addresses a different partition and simply finds nothing.
func (s *Store) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return auth.User{}, err
	}
	if err := checkID("user id", id); err != nil {
		return auth.User{}, err
	}
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(userPK(tenantID, id), skProfile),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.User{}, wrap("get user", err)
	}
	if len(out.Item) == 0 {
		return auth.User{}, ErrUserNotFound
	}
	return userFromItem(out.Item)
}

// UpdateProfile sets the two name fields and returns the updated user.
//
// An empty name REMOVEs the attribute instead of writing "": the omission rule
// in §5 is what lets other conditions rely on attribute_not_exists, and it
// round-trips identically because a missing string decodes to "".
func (s *Store) UpdateProfile(ctx context.Context, userID, tenantID, firstName, lastName string) (auth.User, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return auth.User{}, err
	}
	if err := checkID("user id", userID); err != nil {
		return auth.User{}, err
	}

	set := []string{"#updatedAt = :now"}
	remove := []string{}
	values := map[string]types.AttributeValue{":now": avS(formatTime(s.nowUTC()))}
	for _, f := range []struct {
		attr, alias, value string
	}{
		{attrFirstName, ":first", firstName},
		{attrLastName, ":last", lastName},
	} {
		if f.value == "" {
			remove = append(remove, "#"+f.attr)
			continue
		}
		set = append(set, "#"+f.attr+" = "+f.alias)
		values[f.alias] = avS(f.value)
	}

	out, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       key(userPK(tenantID, userID), skProfile),
		UpdateExpression:          aws.String(updateExpression(set, remove)),
		ConditionExpression:       aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames:  exprNames(attrPK, attrFirstName, attrLastName, attrUpdatedAt),
		ExpressionAttributeValues: values,
		ReturnValues:              types.ReturnValueAllNew,
	})
	if err != nil {
		if isConditionFailed(err) {
			return auth.User{}, ErrUserNotFound
		}
		return auth.User{}, wrap("update profile", err)
	}
	return userFromItem(out.Attributes)
}

// DeleteUser removes the user's whole item collection plus the two items outside
// it that this store wrote: the email-uniqueness item and the tenant membership.
//
// Sessions are swept through GSI1, which is eventually consistent — a session
// created microseconds earlier can be missed. That is acceptable and not papered
// over: the profile is gone by then, so Service.Refresh's GetUserByID fails and
// the surviving session cannot mint a token. Refresh pointers are left to TTL for
// the same reason; a pointer to a deleted session resolves to nothing.
func (s *Store) DeleteUser(ctx context.Context, userID, tenantID string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}

	// The user collection holds only META#, PROFILE and ROLE# — all bounded —
	// so an unconditioned Query on the partition is safe (§2.2).
	collection, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                 aws.String(s.table),
		KeyConditionExpression:    aws.String("#PK = :pk"),
		ExpressionAttributeNames:  exprNames(attrPK),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(userPK(tenantID, userID))},
		ConsistentRead:            aws.Bool(true),
	}, maxUserCollectionItems)
	if err != nil {
		return wrap("query user collection", err)
	}

	var profile map[string]types.AttributeValue
	keys := make([]map[string]types.AttributeValue, 0, len(collection)+8)
	for _, it := range collection {
		if getS(it, attrSK) == skProfile {
			profile = it
		}
		keys = append(keys, key(getS(it, attrPK), getS(it, attrSK)))
	}
	if profile == nil {
		return ErrUserNotFound
	}

	keys = append(keys,
		key(emailPK(tenantID, getS(profile, attrEmail)), skEmail),
		key(tenantPK(tenantID), memberSK(userID)),
	)

	// Drop the single-use pointers the profile still names. They would expire on
	// their own, but the reference deletes them (memory_store.go:99-110) and a
	// pointer outliving its user is needless garbage.
	// Driven off pointerFamilies rather than a hand-written list, so a family
	// added later cannot leave its pointers behind.
	for _, f := range pointerFamilies {
		if hash := getS(profile, f.hashAttr); hash != "" {
			keys = append(keys, key(f.pk(hash), skToken))
		}
	}

	sessionKeys, err := s.sessionKeysForUser(ctx, userID, tenantID)
	if err != nil {
		return err
	}
	keys = append(keys, sessionKeys...)

	// The OAuth bindings and their by-id pointers (data-model.md #6, "links").
	// Swept whether or not this deployment wired the LinkedAccountStore: the items
	// outlive the interface that wrote them, and a binding left behind would keep
	// resolving FindByProvider to a user who no longer exists — which
	// HandleCallback answers with ErrInvalidCredentials rather than by creating a
	// fresh account, so the provider identity would be stranded. Like the session
	// sweep this goes through GSI1 and is therefore eventually consistent; a link
	// written microseconds earlier can be missed, and is harmless for the same
	// reason.
	linkKeys, err := s.linkKeysForUser(ctx, userID)
	if err != nil {
		return err
	}
	keys = append(keys, linkKeys...)

	if err := s.deleteKeys(ctx, keys); err != nil {
		return wrap("delete user", err)
	}
	return nil
}

// updateExpression joins the SET and REMOVE clauses, omitting an empty one:
// DynamoDB rejects "SET" or "REMOVE" with nothing after it.
func updateExpression(set, remove []string) string {
	expr := ""
	if len(set) > 0 {
		expr = "SET " + strings.Join(set, ", ")
	}
	if len(remove) > 0 {
		if expr != "" {
			expr += " "
		}
		expr += "REMOVE " + strings.Join(remove, ", ")
	}
	return expr
}
