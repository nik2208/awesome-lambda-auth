package dynamodb

import (
	"context"
	"fmt"
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

// issueSingleUseToken writes the hash onto the profile and a pointer item that
// maps the hash back to the user (data-model.md #19). The pointer is what makes
// the tenant-less GetUserBy*TokenHash lookups possible at all: the profile lives
// under USER#<t>#<u> and the method carries neither <t> nor <u>.
//
// A previous token's pointer is not deleted. It is a hint only — once the
// profile's hash has moved on, the consume condition below can never match it —
// and TTL reaps it.
func (s *Store) issueSingleUseToken(ctx context.Context, f tokenFamily, userID, tenantID, tokenHash string, expiry time.Time) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}
	if err := checkHash(f.name+" token hash", tokenHash); err != nil {
		return err
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
				TableName:                aws.String(s.table),
				Key:                      key(userPK(tenantID, userID), skProfile),
				UpdateExpression:         aws.String("SET #hash = :hash, #exp = :exp, #updatedAt = :now"),
				ConditionExpression:      aws.String("attribute_exists(#PK)"),
				ExpressionAttributeNames: map[string]string{"#PK": attrPK, "#hash": f.hashAttr, "#exp": f.expAttr, "#updatedAt": attrUpdatedAt},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":hash": avS(tokenHash),
					":exp":  avS(formatTime(expiry)),
					":now":  avS(formatTime(s.nowUTC())),
				},
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
	if err := checkHash(f.name+" token hash", tokenHash); err != nil {
		// An empty hash must not resolve to whatever an empty key happens to
		// hold, and the caller-facing answer is the same either way.
		return auth.User{}, auth.ErrInvalidToken
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
		return auth.User{}, auth.ErrInvalidToken
	}
	if err := checkVersion(ptr.Item, typeToken); err != nil {
		return auth.User{}, err
	}
	userID := getS(ptr.Item, attrUserID)
	tenantID := getS(ptr.Item, attrTenantID)

	if !s.consumeOnRead {
		return s.userByTokenNonAtomic(ctx, f, userID, tenantID, tokenHash)
	}

	out, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:        aws.String(s.table),
		Key:              key(userPK(tenantID, userID), skProfile),
		UpdateExpression: aws.String("REMOVE #hash, #exp"),
		// The expiry is re-checked here rather than trusted to TTL, because TTL
		// deletes on a best-effort basis and a late item must read as absent
		// (§4.5). The store is therefore stricter than the core by exactly the
		// configured clock skew, which the core adds on top of its own check.
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
			return auth.User{}, auth.ErrInvalidToken
		}
		return auth.User{}, wrap("consume "+f.name+" token", err)
	}
	if len(out.Attributes) == 0 {
		// UpdateItem creates a missing item, but the condition on #hash cannot
		// hold for one, so reaching here means the item existed and returned
		// nothing — treat it as a spent token rather than guessing.
		return auth.User{}, auth.ErrInvalidToken
	}
	return userFromItem(out.Attributes)
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
	if len(out.Item) == 0 || getS(out.Item, f.hashAttr) != tokenHash {
		return auth.User{}, auth.ErrInvalidToken
	}
	return userFromItem(out.Item)
}

// clearSingleUseToken is unconditional on the attributes and conditional only on
// the user existing. That matters: REMOVE of an already-removed attribute
// succeeds, so the call stays idempotent after the consuming read above. A
// condition on attribute_exists(#hash) would instead fail the second half of
// ResetPassword — after the password had already been changed.
func (s *Store) clearSingleUseToken(ctx context.Context, f tokenFamily, userID, tenantID string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}
	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                aws.String(s.table),
		Key:                      key(userPK(tenantID, userID), skProfile),
		UpdateExpression:         aws.String("REMOVE #hash, #exp"),
		ConditionExpression:      aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames: map[string]string{"#PK": attrPK, "#hash": f.hashAttr, "#exp": f.expAttr},
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrUserNotFound
		}
		return wrap("clear "+f.name+" token", err)
	}
	return nil
}
