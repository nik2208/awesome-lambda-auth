package dynamodb

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// The four optional single-use stores the auth core discovers by type assertion:
// MagicLinkStore, SMSStore, EmailVerificationStore and EmailChangeStore
// (store.go:42-76). Every one of them is issue → consume-exactly-once → clear,
// so all twelve token methods below are three lines each and the behaviour lives
// in the shared primitive in tokens.go. Two methods are not token-shaped and do
// have bodies here: MarkEmailVerified and ApplyEmailChange.
//
// Two neighbours that are *not* here, so that reads as a decision too. TOTPStore
// and UserPhoneStore have no single-use semantics and live in totp.go with the
// other plain profile writes (§1.1 #9, #9b). And there is no account-link token
// family: v0.2.0 keeps that token in PendingLinkStore under the
// "link-token:<sha256>" namespace rather than on the profile, so it is
// pending_links.go's business and data-model.md §8.5 is withdrawn.
//
// All four are invisible to the compiler at the call site, which is exactly why
// they are pinned here: a signature that drifted would turn into a 500 on the
// wire ("store does not implement …") with nothing failing to build. See
// interfaces.go for the convention.
var (
	_ auth.MagicLinkStore         = (*Store)(nil)
	_ auth.SMSStore               = (*Store)(nil)
	_ auth.EmailVerificationStore = (*Store)(nil)
	_ auth.EmailChangeStore       = (*Store)(nil)
)

// UpdateMagicLinkToken is part of MagicLinkStore.
func (s *Store) UpdateMagicLinkToken(ctx context.Context, userID, tenantID, tokenHash string, expiry time.Time) error {
	return s.issueSingleUseToken(ctx, familyMagic, userID, tenantID, tokenHash, expiry)
}

// GetUserByMagicLinkTokenHash is part of MagicLinkStore. It consumes the link.
//
// Service.verifyMagicLink burns the link before it compares the owner and before
// it mints anything (service.go:342-351), and the reference does the same inside
// its strategy, so a consuming read is parity rather than a deviation.
func (s *Store) GetUserByMagicLinkTokenHash(ctx context.Context, tokenHash string) (auth.User, error) {
	return s.userBySingleUseToken(ctx, familyMagic, tokenHash)
}

// ClearMagicLinkToken is part of MagicLinkStore.
func (s *Store) ClearMagicLinkToken(ctx context.Context, userID, tenantID string) error {
	return s.clearSingleUseToken(ctx, familyMagic, userID, tenantID)
}

// UpdateSMSCode is part of SMSStore.
func (s *Store) UpdateSMSCode(ctx context.Context, userID, tenantID, codeHash string, expiry time.Time) error {
	return s.issueSingleUseToken(ctx, familySMS, userID, tenantID, codeHash, expiry)
}

// GetUserBySMSCodeHash is part of SMSStore. It consumes the code.
//
// No pointer item is involved: the method already carries the full user key
// (store.go:51), so the conditional write goes straight at the profile. A code
// that does not match burns nothing — the condition simply fails — which
// preserves the reference's retry-until-expiry behaviour, where there is no
// attempt counter and a mistyped digit must not cost the user their code.
//
// The answer to a wrong or expired code is ErrInvalidCode, not ErrInvalidToken:
// MemoryUserStore draws that distinction (memory_store.go:238) and
// SMSVerifyHTTPError is built on it.
func (s *Store) GetUserBySMSCodeHash(ctx context.Context, userID, tenantID, codeHash string) (auth.User, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return auth.User{}, err
	}
	if err := checkID("user id", userID); err != nil {
		return auth.User{}, err
	}
	if err := checkHash(familySMS.name+" code hash", codeHash); err != nil {
		// An empty hash must not match an absent attribute. It cannot here — the
		// condition compares against a stored value — but the caller-facing answer
		// is the same either way, and this keeps it from reaching DynamoDB.
		return auth.User{}, familySMS.invalidErr
	}
	return s.consumeSingleUseToken(ctx, familySMS, userID, tenantID, codeHash)
}

// ClearSMSCode is part of SMSStore. It is an idempotent no-op after the
// consuming read, and still ErrUserNotFound for a user who does not exist —
// which is what MemoryUserStore returns (memory_store.go:246-252) and why this is
// a conditional write rather than the "0 items" data-model.md #25 first claimed.
func (s *Store) ClearSMSCode(ctx context.Context, userID, tenantID string) error {
	return s.clearSingleUseToken(ctx, familySMS, userID, tenantID)
}

// UpdateEmailVerificationToken is part of EmailVerificationStore.
func (s *Store) UpdateEmailVerificationToken(ctx context.Context, userID, tenantID, tokenHash string, expiry time.Time) error {
	return s.issueSingleUseToken(ctx, familyVerify, userID, tenantID, tokenHash, expiry)
}

// GetUserByEmailVerificationTokenHash is part of EmailVerificationStore. It
// consumes the token.
func (s *Store) GetUserByEmailVerificationTokenHash(ctx context.Context, tokenHash string) (auth.User, error) {
	return s.userBySingleUseToken(ctx, familyVerify, tokenHash)
}

// MarkEmailVerified is part of EmailVerificationStore (data-model.md #8).
//
// Not conditional on the current value: Service.VerifyEmail sets it to true after
// consuming a token and the magic-link path sets it opportunistically
// (service.go:352-357), so an idempotent write is what both callers want.
func (s *Store) MarkEmailVerified(ctx context.Context, userID, tenantID string, verified bool) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}
	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                aws.String(s.table),
		Key:                      key(userPK(tenantID, userID), skProfile),
		UpdateExpression:         aws.String("SET #isEmailVerified = :v, #updatedAt = :now"),
		ConditionExpression:      aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames: exprNames(attrPK, attrEmailVerified, attrUpdatedAt),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":v":   &types.AttributeValueMemberBOOL{Value: verified},
			":now": avS(formatTime(s.nowUTC())),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrUserNotFound
		}
		return wrap("mark email verified", err)
	}
	return nil
}

// ClearEmailVerificationToken is part of EmailVerificationStore.
func (s *Store) ClearEmailVerificationToken(ctx context.Context, userID, tenantID string) error {
	return s.clearSingleUseToken(ctx, familyVerify, userID, tenantID)
}

// UpdateEmailChangeToken is part of EmailChangeStore.
//
// The pending address is written with the token, in the same conditional update,
// so the two cannot get out of step: there is never a token whose target address
// is a different request's, and never a pending address with no token behind it.
// The address is normalized here for the same reason GetUserByEmail normalizes —
// MemoryUserStore does it at exactly this point (memory_store.go:341) and the
// uniqueness item's key must match the one login will compute.
func (s *Store) UpdateEmailChangeToken(ctx context.Context, userID, tenantID, pendingEmail, tokenHash string, expiry time.Time) error {
	pendingEmail = normalizeEmail(pendingEmail)
	if err := checkEmail(pendingEmail); err != nil {
		return err
	}
	return s.issueSingleUseToken(ctx, familyEchg, userID, tenantID, tokenHash, expiry,
		tokenExtra{attr: attrPendingEmail, value: pendingEmail})
}

// GetUserByEmailChangeTokenHash is part of EmailChangeStore. It consumes the
// token but leaves pendingEmail on the profile, because ApplyEmailChange — which
// the core calls next and which carries no address of its own — reads it from
// there (service.go:472-479).
func (s *Store) GetUserByEmailChangeTokenHash(ctx context.Context, tokenHash string) (auth.User, error) {
	return s.userBySingleUseToken(ctx, familyEchg, tokenHash)
}

// ApplyEmailChange promotes pendingEmail to email, moving the uniqueness item
// with it (data-model.md #22).
//
// ApplyEmailChange(ctx, userID, tenantID) carries no address at all, so the
// current and pending values have to be read before the transaction can name the
// two uniqueness keys. That read does not decide anything: the decision is the
// transaction's own conditions, and the profile update is conditional on both
// values still being the ones that were read. If a concurrent
// UpdateEmailChangeToken re-pointed pendingEmail, or another ApplyEmailChange won
// the race, this one is refused rather than applying an address whose token has
// been superseded — the "must not apply a stale change" requirement, expressed
// where DynamoDB can enforce it.
//
// Three writes, one transaction:
//
//	Put    EMAIL#<t>#<new>  if attribute_not_exists(PK)   -> ErrUserExists
//	Delete EMAIL#<t>#<old>
//	Update USER#<t>#<u>/PROFILE  SET email = :new REMOVE pendingEmail
//	       if attribute_exists(PK) AND email = :old AND pendingEmail = :new
//
// It has to be a transaction and not three writes for the same reason CreateUser
// does: uniqueness in DynamoDB is a separate item guarded by
// attribute_not_exists, and a half-applied change would either strand the old
// address or lose the new one.
func (s *Store) ApplyEmailChange(ctx context.Context, userID, tenantID string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}

	profile, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(userPK(tenantID, userID), skProfile),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return wrap("get user for email change", err)
	}
	if len(profile.Item) == 0 {
		return ErrUserNotFound
	}
	if err := checkVersion(profile.Item, typeUser); err != nil {
		return err
	}
	current := getS(profile.Item, attrEmail)
	pending := getS(profile.Item, attrPendingEmail)

	if pending == "" {
		// Nothing to promote. MemoryUserStore would happily overwrite the address
		// with the empty string here (memory_store.go:376) and orphan the
		// uniqueness item; that is a bug, not a semantic to reproduce.
		return ErrNoPendingEmailChange
	}
	if err := checkEmail(pending); err != nil {
		return err
	}
	if pending == current {
		// The reference reaches ErrUserExists by a different route — old and new
		// hash to one map key, which is therefore already taken
		// (memory_store.go:370-374) — and the answer is the same. Returning early
		// also avoids handing DynamoDB a transaction with two operations on one
		// item, which it rejects outright.
		return auth.ErrUserExists
	}

	err = s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName: aws.String(s.table),
				Item: item{}.
					sAlways(attrPK, emailPK(tenantID, pending)).
					sAlways(attrSK, skEmail).
					stamp(typeEmail).
					sAlways(attrUserID, userID).
					sAlways(attrTenantID, tenantID),
				ConditionExpression:      aws.String("attribute_not_exists(#PK)"),
				ExpressionAttributeNames: exprNames(attrPK),
			}},
			// Unconditional: the address being released is this user's by
			// definition, and a missing item is a delete that succeeds.
			{Delete: &types.Delete{
				TableName: aws.String(s.table),
				Key:       key(emailPK(tenantID, current), skEmail),
			}},
			{Update: &types.Update{
				TableName:           aws.String(s.table),
				Key:                 key(userPK(tenantID, userID), skProfile),
				UpdateExpression:    aws.String("SET #email = :new, #updatedAt = :now REMOVE #pendingEmail"),
				ConditionExpression: aws.String("attribute_exists(#PK) AND #email = :old AND #pendingEmail = :new"),
				ExpressionAttributeNames: map[string]string{
					"#PK": attrPK, "#email": attrEmail, "#pendingEmail": attrPendingEmail, "#updatedAt": attrUpdatedAt,
				},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":new": avS(pending),
					":old": avS(current),
					":now": avS(formatTime(s.nowUTC())),
				},
				// The pre-image is how "the user is gone" is told apart from "the
				// pending change moved under us" without a second read.
				ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
			}},
		},
	})
	if err != nil {
		if reasons, ok := txConditionFailures(err); ok {
			if _, failed := txFailedAt(reasons, 0); failed {
				return auth.ErrUserExists
			}
			if pre, failed := txFailedAt(reasons, 2); failed {
				if len(pre) == 0 {
					return ErrUserNotFound
				}
				// The change this call was confirming is no longer the pending one.
				// ErrInvalidToken is both true and the error the core's own
				// mapping already turns into "Invalid email-change token"
				// (wire_password_email.go:175-184).
				return auth.ErrInvalidToken
			}
		}
		return wrap("apply email change", err)
	}
	return nil
}

// ClearEmailChangeToken is part of EmailChangeStore. It drops the pending
// address along with the token, matching MemoryUserStore
// (memory_store.go:390-395); after a successful ApplyEmailChange the address is
// already gone and the REMOVE is a no-op.
func (s *Store) ClearEmailChangeToken(ctx context.Context, userID, tenantID string) error {
	return s.clearSingleUseToken(ctx, familyEchg, userID, tenantID)
}
