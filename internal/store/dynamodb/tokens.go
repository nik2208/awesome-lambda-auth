package dynamodb

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

const attrFamily = "family"

// UpdatePassword is part of UserPasswordStore.
func (s *Store) UpdatePassword(ctx context.Context, userID, tenantID, passwordHash string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}
	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                aws.String(s.table),
		Key:                      key(userPK(tenantID, userID), skProfile),
		UpdateExpression:         aws.String("SET #passwordHash = :hash, #updatedAt = :now"),
		ConditionExpression:      aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames: exprNames(attrPK, attrPasswordHash, attrUpdatedAt),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":hash": avS(passwordHash),
			":now":  avS(formatTime(s.nowUTC())),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrUserNotFound
		}
		return wrap("update password", err)
	}
	return nil
}

// UpdateResetToken is part of UserPasswordStore.
func (s *Store) UpdateResetToken(ctx context.Context, userID, tenantID, tokenHash string, expiry time.Time) error {
	return s.issueSingleUseToken(ctx, familyReset, userID, tenantID, tokenHash, expiry)
}

// GetUserByResetTokenHash is part of UserPasswordStore.
func (s *Store) GetUserByResetTokenHash(ctx context.Context, tokenHash string) (auth.User, error) {
	return s.userBySingleUseToken(ctx, familyReset, tokenHash)
}

// ClearResetToken is part of UserPasswordStore.
func (s *Store) ClearResetToken(ctx context.Context, userID, tenantID string) error {
	return s.clearSingleUseToken(ctx, familyReset, userID, tenantID)
}

// tokenExtra is an additional profile attribute written when a token is issued.
// Only email change uses one — the address the change is to — and it travels
// with the token so that issuing, consuming and clearing cannot disagree about
// which pending address belongs to which token.
type tokenExtra struct {
	attr  string
	value string
}

// issueSingleUseToken writes the hash onto the profile and, for a pointer-backed
// family, a pointer item that maps the hash back to the user (data-model.md #19).
// The pointer is what makes the tenant-less GetUserBy*TokenHash lookups possible
// at all: the profile lives under USER#<t>#<u> and those methods carry neither
// <t> nor <u>.
//
// Replacing an outstanding token invalidates the previous one, matching
// MemoryUserStore, which deletes the old hash from its index (memory_store.go:180-182,
// :279-281, :338-340). Here the previous *pointer* is left alone: it is a hint
// only — once the profile's hash has moved on, the consume condition can never
// match it — and TTL reaps it. Deleting it would need a third transaction item
// and would buy nothing, because the profile is the authority.
//
// A pointerless family (SMS) is one conditional UpdateItem. MemoryUserStore's
// UpdateSMSCode likewise keeps no index and simply overwrites
// (memory_store.go:220-231).
func (s *Store) issueSingleUseToken(ctx context.Context, f tokenFamily, userID, tenantID, tokenHash string, expiry time.Time, extras ...tokenExtra) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}
	if err := checkHash(f.name+" hash", tokenHash); err != nil {
		return err
	}
	if len(extras) != len(f.extraIssueAttrs) {
		return fmt.Errorf("dynamodb: %s token takes %d extra attribute(s), got %d", f.name, len(f.extraIssueAttrs), len(extras))
	}

	// The profile write is identical in both branches, so the SET clause is built
	// once. A family cannot end up with a different update depending on whether it
	// has a pointer.
	set := []string{"#hash = :hash", "#exp = :exp", "#updatedAt = :now"}
	names := map[string]string{"#PK": attrPK, "#hash": f.hashAttr, "#exp": f.expAttr, "#updatedAt": attrUpdatedAt}
	values := map[string]types.AttributeValue{
		":hash": avS(tokenHash),
		":exp":  avS(formatTime(expiry)),
		":now":  avS(formatTime(s.nowUTC())),
	}
	for i, e := range extras {
		alias, valueAlias := fmt.Sprintf("#x%d", i), fmt.Sprintf(":x%d", i)
		names[alias] = e.attr
		values[valueAlias] = avS(e.value)
		set = append(set, alias+" = "+valueAlias)
	}
	profileUpdate := "SET " + strings.Join(set, ", ")

	if !f.hasPointer() {
		_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
			TableName:        aws.String(s.table),
			Key:              key(userPK(tenantID, userID), skProfile),
			UpdateExpression: aws.String(profileUpdate),
			// UpdateItem creates a missing item, so without this an issue for a
			// user who does not exist would silently manufacture a profile-shaped
			// item holding nothing but a token.
			ConditionExpression:       aws.String("attribute_exists(#PK)"),
			ExpressionAttributeNames:  names,
			ExpressionAttributeValues: values,
		})
		if err != nil {
			if isConditionFailed(err) {
				return ErrUserNotFound
			}
			return wrap("issue "+f.name+" code", err)
		}
		return nil
	}

	pointer := item{}.
		sAlways(attrPK, f.pk(tokenHash)).
		sAlways(attrSK, skToken).
		stamp(typeToken).
		sAlways(attrFamily, f.name).
		sAlways(attrUserID, userID).
		sAlways(attrTenantID, tenantID).
		ttl(expiry)

	err := s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Update: &types.Update{
				TableName:                 aws.String(s.table),
				Key:                       key(userPK(tenantID, userID), skProfile),
				UpdateExpression:          aws.String(profileUpdate),
				ConditionExpression:       aws.String("attribute_exists(#PK)"),
				ExpressionAttributeNames:  names,
				ExpressionAttributeValues: values,
			}},
			{Put: &types.Put{
				TableName: aws.String(s.table),
				Item:      pointer,
				// attribute_not_exists alone would make an ordinary retry of this
				// call fail, so the same (user, tenant) reclaiming its own pointer
				// is allowed. A different owner behind the same hash is a sha256
				// collision and stays loud.
				ConditionExpression:      aws.String("attribute_not_exists(#PK) OR (#userId = :uid AND #tenantId = :tid)"),
				ExpressionAttributeNames: exprNames(attrPK, attrUserID, attrTenantID),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":uid": avS(userID),
					":tid": avS(tenantID),
				},
			}},
		},
	})
	if err != nil {
		if reasons, ok := txConditionFailures(err); ok {
			if _, failed := txFailedAt(reasons, 0); failed {
				return ErrUserNotFound
			}
			if _, failed := txFailedAt(reasons, 1); failed {
				return fmt.Errorf("dynamodb: %s token hash already belongs to another user", f.name)
			}
		}
		return wrap("issue "+f.name+" token", err)
	}
	return nil
}

// userBySingleUseToken resolves a token hash to its user and, by default,
// consumes it in the same call.
//
// The core's flow is three separate store calls — lookup, mutate, clear
// (service.go:246-266) — with nothing atomic across them, so two Lambdas racing
// on one link both pass the lookup. Making the lookup itself the conditional
// write closes that: exactly one caller can satisfy "#hash = :h", and the losers
// get ErrInvalidToken. Clear*Token afterwards is then an idempotent no-op.
//
// The cost is fail-closed behaviour: if the step after this one fails, the token
// is already burned and the user must request a new link. That is the right
// posture for auth, and it matches the reference's magic-link behaviour, which
// burns the token even when the check that follows fails.
func (s *Store) userBySingleUseToken(ctx context.Context, f tokenFamily, tokenHash string) (auth.User, error) {
	if !f.hasPointer() {
		// Unreachable through the interface methods; here so that adding a family
		// and wiring it to the wrong helper fails loudly instead of reading a
		// partition key with no prefix.
		return auth.User{}, fmt.Errorf("dynamodb: %s has no pointer item to resolve", f.name)
	}
	if err := checkHash(f.name+" token hash", tokenHash); err != nil {
		// An empty hash must not resolve to whatever an empty key happens to
		// hold, and the caller-facing answer is the same either way.
		return auth.User{}, f.invalidErr
	}

	ptr, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(f.pk(tokenHash), skToken),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.User{}, wrap("get "+f.name+" pointer", err)
	}
	if len(ptr.Item) == 0 {
		return auth.User{}, f.invalidErr
	}
	if err := checkVersion(ptr.Item, typeToken); err != nil {
		return auth.User{}, err
	}
	// Both come off an item this store wrote, never off the request: the tenant a
	// downstream key is built from is re-derived from stored state, which is what
	// keeps a capability-keyed lookup tenant-safe (§3).
	userID := getS(ptr.Item, attrUserID)
	tenantID := getS(ptr.Item, attrTenantID)

	return s.consumeSingleUseToken(ctx, f, userID, tenantID, tokenHash)
}

// consumeSingleUseToken is the one conditional write every family consumes
// through, whether its hash arrived via a pointer or straight from the caller.
//
// The condition is the whole guarantee: it fails if the hash does not match the
// one on the profile (unknown, superseded or already consumed) and if the stored
// expiry is not in the future. Exactly one concurrent caller can satisfy it.
func (s *Store) consumeSingleUseToken(ctx context.Context, f tokenFamily, userID, tenantID, tokenHash string) (auth.User, error) {
	if !s.consumeOnRead {
		return s.userByTokenNonAtomic(ctx, f, userID, tenantID, tokenHash)
	}

	out, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key:       key(userPK(tenantID, userID), skProfile),
		// Only the hash and the expiry. Anything else the token carried — the
		// pending address, for email change — must outlive the consume, because
		// the core reads it back through a later method (§4.1).
		UpdateExpression: aws.String("REMOVE #hash, #exp"),
		// The expiry is re-checked here rather than trusted to TTL, because TTL
		// deletes on a best-effort basis and a late item must read as absent
		// (§4.5). The comparison is lexicographic, which is chronological only
		// because tsLayout pads the fraction to nine digits — see item.go. The
		// store is therefore stricter than the core by exactly the configured
		// clock skew, which the core adds on top of its own check.
		ConditionExpression:      aws.String("#hash = :hash AND #exp > :now"),
		ExpressionAttributeNames: map[string]string{"#hash": f.hashAttr, "#exp": f.expAttr},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":hash": avS(tokenHash),
			":now":  avS(formatTime(s.nowUTC())),
		},
		// ALL_OLD is the point of the design: the pre-image is exactly the
		// auth.User this method must return, including the hash and expiry the
		// core checks next.
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		if isConditionFailed(err) {
			// A lost condition is an authentication outcome, not a fault: the
			// value was unknown, spent, superseded or expired. Anything else is a
			// genuine failure and must not be flattened into it.
			return auth.User{}, f.invalidErr
		}
		return auth.User{}, wrap("consume "+f.name+" token", err)
	}
	if len(out.Attributes) == 0 {
		// UpdateItem creates a missing item, but the condition on #hash cannot
		// hold for one, so reaching here means the item existed and returned
		// nothing — treat it as spent rather than guessing.
		return auth.User{}, f.invalidErr
	}
	return userFromItem(out.Attributes)
}

// consumeItemOnce is the same guarantee as consumeSingleUseToken for a
// credential that *is* an item rather than two attributes of one.
//
// It is a sibling rather than a call into it because the atomic write differs in
// exactly one way that cannot be parameterised: there, the secret is an attribute
// of a user profile that must survive the consume, so the write is a conditional
// UpdateItem that REMOVEs two attributes; here, the secret is the partition key,
// so the write is a conditional DeleteItem of the whole item. Everything that
// makes either one correct is identical and deliberately kept identical:
//
//   - the expiry is re-checked inside the condition rather than trusted to TTL,
//     because TTL deletes on a best-effort basis and a late item must read as
//     absent (§4.5);
//   - the comparison is lexicographic, which is chronological only because
//     tsLayout pads the fraction to nine digits (item.go);
//   - ALL_OLD returns the pre-image, which is the value the caller needs;
//   - exactly one concurrent caller can satisfy the condition, and a lost
//     condition is an authentication outcome, never a fault — only
//     ConditionalCheckFailedException takes that branch.
//
// The pre-image on failure tells "no such item" from "it was there but expired":
// an empty one means absent. The expired item is left for TTL rather than
// deleted, so the classification stays available to a retry; a later call sees
// the same answer either way.
func (s *Store) consumeItemOnce(ctx context.Context, pk, sk, expAttr string, absent, expired error) (map[string]types.AttributeValue, error) {
	out, err := s.api.DeleteItem(ctx, &awsddb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key:       key(pk, sk),
		// attribute_exists(#PK) is not redundant with the expiry clause: an item
		// with no expiry attribute at all is a legitimate no-deadline entry, and
		// without the existence test the condition would hold for a missing item.
		ConditionExpression:      aws.String("attribute_exists(#PK) AND (attribute_not_exists(#exp) OR #exp > :now)"),
		ExpressionAttributeNames: map[string]string{"#PK": attrPK, "#exp": expAttr},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now": avS(formatTime(s.nowUTC())),
		},
		ReturnValues:                        types.ReturnValueAllOld,
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err != nil {
		if pre, failed := conditionFailedItem(err); failed {
			if len(pre) == 0 {
				return nil, absent
			}
			return nil, expired
		}
		return nil, wrap("consume "+sk+" item", err)
	}
	if len(out.Attributes) == 0 {
		// DeleteItem of a missing item succeeds, but attribute_exists(#PK) cannot
		// hold for one, so reaching here means the pre-image did not come back.
		// Treat it as spent rather than guessing at what was consumed.
		return nil, absent
	}
	return out.Attributes, nil
}

// userByTokenNonAtomic reproduces the reference's read-then-clear for
// strict-parity testing (Options.NonAtomicSingleUseTokens). The hash is still
// compared against the profile, because unlike the reference's map the pointer
// item outlives the token it names and a rotated-out pointer must not resolve.
func (s *Store) userByTokenNonAtomic(ctx context.Context, f tokenFamily, userID, tenantID, tokenHash string) (auth.User, error) {
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(userPK(tenantID, userID), skProfile),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.User{}, wrap("get user for "+f.name+" token", err)
	}
	if len(out.Item) == 0 || !secureEqual(getS(out.Item, f.hashAttr), tokenHash) {
		return auth.User{}, f.invalidErr
	}
	return userFromItem(out.Item)
}

// clearSingleUseToken is unconditional on the attributes and conditional only on
// the user existing. That matters: REMOVE of an already-removed attribute
// succeeds, so the call stays idempotent after the consuming read above. A
// condition on attribute_exists(#hash) would instead fail the second half of
// ResetPassword — after the password had already been changed.
//
// extraClearAttrs go with it, which is how ClearEmailChangeToken drops the
// pending address as well as the token (memory_store.go:390-395).
func (s *Store) clearSingleUseToken(ctx context.Context, f tokenFamily, userID, tenantID string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}

	remove := []string{"#hash", "#exp"}
	names := map[string]string{"#PK": attrPK, "#hash": f.hashAttr, "#exp": f.expAttr}
	for i, attr := range f.extraClearAttrs {
		alias := fmt.Sprintf("#x%d", i)
		names[alias] = attr
		remove = append(remove, alias)
	}

	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                aws.String(s.table),
		Key:                      key(userPK(tenantID, userID), skProfile),
		UpdateExpression:         aws.String("REMOVE " + strings.Join(remove, ", ")),
		ConditionExpression:      aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames: names,
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrUserNotFound
		}
		return wrap("clear "+f.name+" token", err)
	}
	return nil
}

// secureEqual is a constant-time string comparison, used on the one path that
// compares a stored hash in this process rather than in a ConditionExpression.
// It mirrors the core's own helper (security.go) so the parity escape hatch does
// not quietly have a weaker comparison than the code it is imitating.
//
// The consuming path needs no equivalent: the comparison happens inside
// DynamoDB, where the timing is not the caller's to observe, and what is being
// compared is a sha256 digest rather than the secret itself.
func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
