package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// TOTPStore, the whole interface: one method (store.go:56-58).
//
// Enrolment is stateless in the reference and in the core. POST /2fa/setup
// generates a secret and hands it straight to the client without persisting it
// (service.go:482-488 — SetupTOTP does not touch any store), and
// POST /2fa/verify-setup receives that same secret back in the request body,
// validates a code against it, and only then asks the store to keep it
// (service.go:490-499). So what this method persists is the *confirmed* secret,
// never a pending one, and there is no intermediate item type for a setup that
// was started and abandoned — which is why §1.3's single-use machinery does not
// apply here and this is a plain conditional update of the profile (#9).
//
// Two consequences worth being explicit about:
//
//   - The secret is a bearer credential at rest: anyone holding it can mint valid
//     codes forever. It therefore lives on exactly one item, the profile, and is
//     excluded from GSI1 by construction (table.go's gsi1Projection), for the
//     same reason passwordHash and refreshHash are.
//   - There is no re-enrolment race to lose. Both callers pass a secret they
//     already hold, so a second VerifyTOTPSetup simply replaces the first; the
//     write is last-one-wins exactly as MemoryUserStore's is
//     (memory_store.go:259-270).

// The two plain profile-writing capabilities. UserPhoneStore is declared in the
// core's account.go rather than in store.go, beside the POST /add-phone route
// that needs it, which is why a derivation that read store.go, oauth.go,
// api_keys.go and telemetry.go missed it entirely; it was found by driving the
// routes (cmd/auth's store sweep), not by reading, and it is pinned so it cannot
// be lost again. See interfaces.go for the convention.
var (
	_ auth.TOTPStore      = (*Store)(nil)
	_ auth.UserPhoneStore = (*Store)(nil)
)

// UpdateTOTPSecret is part of auth.TOTPStore. It is called with
// (secret, true) by VerifyTOTPSetup and with ("", false) by DisableTOTP.
//
// An empty secret REMOVEs the attribute rather than writing "": §5's omission
// rule is what keeps attribute_not_exists meaningful across the table, and it
// round-trips identically because a missing string decodes to "". It also means
// disabling 2FA actually erases the shared secret instead of leaving a
// zero-length copy of a credential on the item.
//
// enabled follows the argument rather than the secret. A caller that passes
// ("", true) leaves TOTP enabled with nothing to verify against, which is what
// MemoryUserStore does too; VerifyTOTP then refuses that user
// (service.go:502-505), so reproducing it faithfully is safer than inventing a
// correction the reference does not have.
func (s *Store) UpdateTOTPSecret(ctx context.Context, userID, tenantID, secret string, enabled bool) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}

	set := []string{"#isTotpEnabled = :enabled", "#updatedAt = :now"}
	var remove []string
	values := map[string]types.AttributeValue{
		":enabled": &types.AttributeValueMemberBOOL{Value: enabled},
		":now":     avS(formatTime(s.nowUTC())),
	}
	if secret == "" {
		remove = append(remove, "#totpSecret")
	} else {
		set = append(set, "#totpSecret = :secret")
		values[":secret"] = avS(secret)
	}

	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:        aws.String(s.table),
		Key:              key(userPK(tenantID, userID), skProfile),
		UpdateExpression: aws.String(updateExpression(set, remove)),
		// Not optional: UpdateItem creates a missing item, so without this an
		// enrolment for a user who does not exist would manufacture a
		// profile-shaped item holding nothing but a TOTP secret — and answer
		// success where MemoryUserStore answers "user not found"
		// (memory_store.go:262-264).
		ConditionExpression:       aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames:  exprNames(attrPK, attrTOTPSecret, attrTOTPEnabled, attrUpdatedAt),
		ExpressionAttributeValues: values,
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrUserNotFound
		}
		return wrap("update totp secret", err)
	}
	return nil
}

// UpdatePhoneNumber is the whole of auth.UserPhoneStore (account.go:18-25), the
// capability behind POST /add-phone.
//
// It lives here rather than with the other profile writers because it was found
// the same way: not by reading store.go, which is where the port's derivation
// looked (data-model.md §1), but by driving every mounted route and seeing which
// one still answered 501. The interface is declared in account.go, alongside the
// route that needs it, and is easy to miss for exactly that reason. There is no
// item type of its own — the number is already part of the profile
// (data-model.md §5) — so the only thing this closes is a missing method.
//
// An empty number REMOVEs the attribute, which is §5's omission rule and also
// what the interface means by clearing: the reference's phoneNumber is nullable
// and AddPhoneInput documents an empty value as "clears the number".
func (s *Store) UpdatePhoneNumber(ctx context.Context, userID, tenantID, phoneNumber string) (auth.User, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return auth.User{}, err
	}
	if err := checkID("user id", userID); err != nil {
		return auth.User{}, err
	}

	set := []string{"#updatedAt = :now"}
	var remove []string
	values := map[string]types.AttributeValue{":now": avS(formatTime(s.nowUTC()))}
	if phoneNumber == "" {
		remove = append(remove, "#"+attrPhoneNumber)
	} else {
		set = append(set, "#"+attrPhoneNumber+" = :phone")
		values[":phone"] = avS(phoneNumber)
	}

	out, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       key(userPK(tenantID, userID), skProfile),
		UpdateExpression:          aws.String(updateExpression(set, remove)),
		ConditionExpression:       aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames:  exprNames(attrPK, attrPhoneNumber, attrUpdatedAt),
		ExpressionAttributeValues: values,
		// The interface returns the updated user, and ALL_NEW is that user without
		// a second read — the same shape UpdateProfile uses.
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		if isConditionFailed(err) {
			return auth.User{}, ErrUserNotFound
		}
		return auth.User{}, wrap("update phone number", err)
	}
	return userFromItem(out.Attributes)
}
