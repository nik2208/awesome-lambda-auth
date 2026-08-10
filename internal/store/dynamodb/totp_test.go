package dynamodb

import (
	"context"
	"errors"
	"slices"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// newUnenrolledUser is sampleUser with the TOTP fields cleared. sampleUser sets
// them, which would let an enrolment test pass without writing anything.
func newUnenrolledUser(t *testing.T, store *Store, tenantID string) auth.User {
	t.Helper()
	u := sampleUser(tenantID)
	u.IsTOTPEnabled = false
	u.TOTPSecret = ""
	created, err := store.CreateUser(context.Background(), u)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return created
}

func TestUpdateTOTPSecretRoundTrip(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	user := newUnenrolledUser(t, store, "acme")

	const secret = "JBSWY3DPEHPK3PXP"
	if err := store.UpdateTOTPSecret(ctx, user.ID, "acme", secret, true); err != nil {
		t.Fatalf("UpdateTOTPSecret: %v", err)
	}

	got, err := store.GetUserByID(ctx, user.ID, "acme")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.TOTPSecret != secret {
		t.Errorf("TOTPSecret = %q, want %q", got.TOTPSecret, secret)
	}
	if !got.IsTOTPEnabled {
		t.Error("IsTOTPEnabled = false, want true")
	}
	// VerifyTOTP reads both off the user it resolves (service.go:502-505), so the
	// two have to land on the same item and come back together.
	raw := rawItem(t, client, store.table, userPK("acme", user.ID), skProfile)
	if getS(raw, attrTOTPSecret) != secret {
		t.Errorf("raw %s = %q, want %q", attrTOTPSecret, getS(raw, attrTOTPSecret), secret)
	}
	if !getBool(raw, attrTOTPEnabled) {
		t.Errorf("raw %s = false, want true", attrTOTPEnabled)
	}
}

// TestDisableTOTPRemovesTheSecret is the point of the REMOVE branch: disabling
// must erase the shared secret, not leave a zero-length copy of a credential on
// the item.
func TestDisableTOTPRemovesTheSecret(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	user := newUnenrolledUser(t, store, "acme")

	if err := store.UpdateTOTPSecret(ctx, user.ID, "acme", "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if err := store.UpdateTOTPSecret(ctx, user.ID, "acme", "", false); err != nil {
		t.Fatalf("disable: %v", err)
	}

	raw := rawItem(t, client, store.table, userPK("acme", user.ID), skProfile)
	if _, present := raw[attrTOTPSecret]; present {
		t.Errorf("%s is still present after disabling: %v", attrTOTPSecret, raw[attrTOTPSecret])
	}
	if getBool(raw, attrTOTPEnabled) {
		t.Errorf("raw %s = true, want false", attrTOTPEnabled)
	}
	got, err := store.GetUserByID(ctx, user.ID, "acme")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.TOTPSecret != "" || got.IsTOTPEnabled {
		t.Errorf("after disabling: secret=%q enabled=%v, want empty and false", got.TOTPSecret, got.IsTOTPEnabled)
	}
}

// TestUpdateTOTPSecretForAMissingUser covers the condition that stops UpdateItem
// from manufacturing a profile-shaped item holding nothing but a secret.
func TestUpdateTOTPSecretForAMissingUser(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	ghost := uniqueID("usr")
	err := store.UpdateTOTPSecret(ctx, ghost, "acme", "JBSWY3DPEHPK3PXP", true)
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("UpdateTOTPSecret for a missing user = %v, want ErrUserNotFound", err)
	}
	mustNotExist(t, client, store.table, userPK("acme", ghost), skProfile)
}

// TestUpdateTOTPSecretIsScopedToItsTenant: the tenant is in the partition key, so
// a mismatched tenant addresses a different item and finds nothing to update.
func TestUpdateTOTPSecretIsScopedToItsTenant(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	user := newUnenrolledUser(t, store, "acme")

	if err := store.UpdateTOTPSecret(ctx, user.ID, "other", "JBSWY3DPEHPK3PXP", true); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("cross-tenant UpdateTOTPSecret = %v, want ErrUserNotFound", err)
	}
	got, err := store.GetUserByID(ctx, user.ID, "acme")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.TOTPSecret != "" || got.IsTOTPEnabled {
		t.Errorf("acme's user was mutated by an 'other' tenant write: secret=%q enabled=%v", got.TOTPSecret, got.IsTOTPEnabled)
	}
}

// TestUpdatePhoneNumber covers auth.UserPhoneStore: set, read back, clear.
func TestUpdatePhoneNumber(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	user := newUnenrolledUser(t, store, "acme")

	const phone = "+390987654321"
	updated, err := store.UpdatePhoneNumber(ctx, user.ID, "acme", phone)
	if err != nil {
		t.Fatalf("UpdatePhoneNumber: %v", err)
	}
	// The interface returns the updated user, so the caller must not have to read
	// again to see the change.
	if updated.PhoneNumber != phone {
		t.Errorf("returned PhoneNumber = %q, want %q", updated.PhoneNumber, phone)
	}
	if updated.ID != user.ID || updated.Email != user.Email {
		t.Errorf("returned user = %+v, want the same identity as %q/%q", updated, user.ID, user.Email)
	}

	got, err := store.GetUserByID(ctx, user.ID, "acme")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.PhoneNumber != phone {
		t.Errorf("stored PhoneNumber = %q, want %q", got.PhoneNumber, phone)
	}

	// An empty number clears it, as the reference's nullable phoneNumber does, and
	// clears it by removing the attribute rather than writing "".
	cleared, err := store.UpdatePhoneNumber(ctx, user.ID, "acme", "")
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if cleared.PhoneNumber != "" {
		t.Errorf("after clearing, PhoneNumber = %q, want empty", cleared.PhoneNumber)
	}
	raw := rawItem(t, client, store.table, userPK("acme", user.ID), skProfile)
	if _, present := raw[attrPhoneNumber]; present {
		t.Errorf("%s is still present after clearing: %v", attrPhoneNumber, raw[attrPhoneNumber])
	}
}

func TestUpdatePhoneNumberForAMissingUser(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	ghost := uniqueID("usr")
	if _, err := store.UpdatePhoneNumber(ctx, ghost, "acme", "+390987654321"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("UpdatePhoneNumber for a missing user = %v, want ErrUserNotFound", err)
	}
	mustNotExist(t, client, store.table, userPK("acme", ghost), skProfile)
}

// TestTOTPSecretIsNeverProjectedToTheIndex is a pure unit test, and cheap enough
// to be worth having: a GSI is a second physical copy with its own export and its
// own PITR restore, so a shared secret that reached it would exist in two places
// with two blast radii (§5). Nothing in this build indexes the profile item, but
// the projection list is the thing a future item type would be added to.
func TestTOTPSecretIsNeverProjectedToTheIndex(t *testing.T) {
	t.Parallel()
	for _, secret := range []string{attrTOTPSecret, attrPasswordHash, attrSMSHash, familyReset.hashAttr} {
		if slices.Contains(gsi1Projection, secret) {
			t.Errorf("gsi1Projection includes %q; secrets exist in exactly one place", secret)
		}
	}
}
