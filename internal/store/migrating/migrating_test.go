package migrating

import (
	"errors"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"

	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

func TestImportOnlyNeverReachesTheSource(t *testing.T) {
	t.Parallel()
	email := uniqueEmail("absent")
	dir := newFakeDirectory()
	dir.add(email, map[string]string{"email": email}, "pw")
	m := newMigrating(t, dir) // DualRead defaults to false

	_, err := m.GetUserByEmail(t.Context(), email, "")
	if !errors.Is(err, ddbstore.ErrUserNotFound) {
		t.Fatalf("GetUserByEmail = %v, want ErrUserNotFound", err)
	}
	if getCalls, _ := dir.counts(); getCalls != 0 {
		t.Fatalf("import-only mode called the source %d times; a miss is a miss", getCalls)
	}
}

func TestDualReadProvisionsTheRowWithTheMarker(t *testing.T) {
	t.Parallel()
	email := uniqueEmail("ada")
	dir := newFakeDirectory()
	dir.add(email, map[string]string{
		"email":             email,
		"email_verified":    "true",
		"phone_number":      "+15550100",
		"given_name":        "Ada",
		"family_name":       "Lovelace",
		"custom:department": "analytics",
	}, "pw")
	m := newMigrating(t, dir, func(o *Options) { o.DualRead = true })

	got, err := m.GetUserByEmail(t.Context(), email, "")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got.Email != email || got.FirstName != "Ada" || got.LastName != "Lovelace" || got.PhoneNumber != "+15550100" {
		t.Errorf("provisioned user = %+v", got)
	}
	if !got.IsEmailVerified {
		t.Error("email_verified \"true\" did not carry across")
	}
	// The password is NOT imported, because a user pool yields no hash. The empty
	// value is also what keeps the passwordless initial-password path open.
	if got.PasswordHash != "" {
		t.Errorf("PasswordHash = %q, want empty: a pool yields no hash to import", got.PasswordHash)
	}
	if !markerRecorded(t, m, got.ID) {
		t.Fatal("the provisioned row filed no marker for this pool; the verifier would fail closed")
	}
	if _, leaked := got.Metadata["migration"]; leaked {
		t.Errorf("the marker is on auth.User.Metadata and would reach the wire: %v", got.Metadata)
	}

	// It is persisted, not merely returned: the second lookup is local.
	getBefore, _ := dir.counts()
	again, err := m.GetUserByEmail(t.Context(), email, "")
	if err != nil {
		t.Fatalf("second GetUserByEmail: %v", err)
	}
	if again.ID != got.ID {
		t.Errorf("second lookup returned id %q, want the persisted %q", again.ID, got.ID)
	}
	if getAfter, _ := dir.counts(); getAfter != getBefore {
		t.Error("a local hit reached the source; after the import, that is every lookup")
	}
	// The custom attribute survived the round trip through the profile item.
	imported, _ := again.Metadata[ddbstore.ImportedAttributesKey].(map[string]any)
	if imported["department"] != "analytics" {
		t.Errorf("imported attributes = %v, want department=analytics", again.Metadata[ddbstore.ImportedAttributesKey])
	}
}

// A failed fall-through returns the ORIGINAL miss and never a new error. The
// core maps any GetUserByEmail error to ErrInvalidCredentials on the login path,
// but /register branches on ErrUserExists versus a miss, so a novel error there
// would be a 500 where the route used to answer 201.
func TestDualReadFailureReturnsTheOriginalMiss(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		set  func(*fakeDirectory)
	}{
		{"the pool does not hold the address", func(*fakeDirectory) {}},
		{"the pool could not be reached", func(f *fakeDirectory) { f.getErr = errors.New("network is unreachable") }},
		{"the pool throttled the read", func(f *fakeDirectory) { f.getErr = awsintegration.ErrCognitoThrottled }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := newFakeDirectory()
			tc.set(dir)
			m := newMigrating(t, dir, func(o *Options) { o.DualRead = true })

			_, err := m.GetUserByEmail(t.Context(), uniqueEmail("absent"), "")
			if !errors.Is(err, ddbstore.ErrUserNotFound) {
				t.Fatalf("GetUserByEmail = %v, want the original ErrUserNotFound", err)
			}
		})
	}
}

// A store failure that is not a miss must not fall through: provisioning on a
// timeout could create a duplicate row for a user the table already holds and
// merely failed to return.
func TestDualReadDoesNotFallThroughOnANonMissError(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	// A store pointed at a table that does not exist: every read fails, and none
	// of the failures is a miss. That is the shape of the real hazard — a
	// throttle, a timeout, a table briefly unavailable — and the one this must
	// not treat as "the user is not here".
	m := newMigrating(t, dir, func(o *Options) {
		o.DualRead = true
		o.Inner = newStoreOnAMissingTable(t)
	})

	_, err := m.GetUserByEmail(t.Context(), uniqueEmail("ada"), "")
	if err == nil {
		t.Fatal("a read against a table that does not exist succeeded")
	}
	if errors.Is(err, ddbstore.ErrUserNotFound) {
		t.Fatalf("a store failure was reported as a miss: %v", err)
	}
	if getCalls, _ := dir.counts(); getCalls != 0 {
		t.Errorf("the source was called %d times on a store failure; provisioning there could create a duplicate "+
			"row for a user the table already holds and merely failed to return", getCalls)
	}
}

func TestDualReadIsRateLimited(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	m := newMigrating(t, dir, func(o *Options) {
		o.DualRead = true
		o.SubjectBurst = 2
		o.SubjectPerMinute = 0.0001
	})
	email := uniqueEmail("absent")

	for range 5 {
		if _, err := m.GetUserByEmail(t.Context(), email, ""); !errors.Is(err, ddbstore.ErrUserNotFound) {
			t.Fatalf("GetUserByEmail = %v, want ErrUserNotFound", err)
		}
	}
	if getCalls, _ := dir.counts(); getCalls != 2 {
		t.Fatalf("the source was called %d times against a burst of 2; the bound is not holding", getCalls)
	}
}

// The wrapper must still be every store the wrapped one was. The core finds
// these by type assertion, so a promotion that stopped working would turn into a
// 501 on the wire with nothing failing to build — which is why the compile-time
// assertions exist in migrating.go and why this drives one of them for real.
func TestWrappingDoesNotNarrowTheStore(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	m := newMigrating(t, dir)

	if _, ok := any(m).(auth.UserPasswordStore); !ok {
		t.Fatal("the wrapper is not a UserPasswordStore; the core could not adopt a migrated password through it")
	}
	if _, ok := any(m).(auth.MagicLinkStore); !ok {
		t.Fatal("the wrapper is not a MagicLinkStore; POST /magic-link/send would answer 501")
	}
	if _, ok := any(m).(interface {
		LinkedAccounts() auth.LinkedAccountStore
	}); !ok {
		t.Fatal("the wrapper no longer exposes LinkedAccounts(); the OAuth callback would answer 501")
	}
}

func TestUserFromSourceRefusesARecordWithNoEmail(t *testing.T) {
	t.Parallel()
	rec := awsintegration.CognitoUser{
		Username:   "0cb4e2f4-no-email",
		Attributes: map[string]string{"phone_number": "+15550100"},
	}
	_, err := UserFromSource(rec, nil)
	if !errors.Is(err, ErrNoEmail) {
		t.Fatalf("UserFromSource = %v, want ErrNoEmail", err)
	}
	// The username is named so an operator can find the record at the source.
	if got := err.Error(); got == "" || !contains(got, rec.Username) {
		t.Errorf("the error does not name the record: %q", got)
	}
}

func TestUserFromSourceHonoursTheAttributeMap(t *testing.T) {
	t.Parallel()
	rec := awsintegration.CognitoUser{
		Username: "ada",
		Attributes: map[string]string{
			"email":             "ADA@Example.Test ",
			"email_verified":    "TRUE",
			"custom:department": "analytics",
			"custom:tier":       "gold",
			"locale":            "en-GB",
		},
	}
	attrs := DefaultAttributeMap()
	attrs["custom:tier"] = FieldRole
	attrs["custom:department"] = FieldMetadataPrefix + "dept"
	attrs["locale"] = FieldIgnore

	user, err := UserFromSource(rec, attrs)
	if err != nil {
		t.Fatalf("UserFromSource: %v", err)
	}
	// The address is normalised the way the core and the store normalise it, so
	// the marker, the limiter bucket and the uniqueness item key on one value.
	if user.Email != "ada@example.test" {
		t.Errorf("Email = %q, want it trimmed and lower-cased", user.Email)
	}
	if !user.IsEmailVerified {
		t.Error("email_verified \"TRUE\" was not read as verified")
	}
	if user.Role != "gold" {
		t.Errorf("Role = %q, want the mapped custom:tier", user.Role)
	}
	imported, _ := user.Metadata[ddbstore.ImportedAttributesKey].(map[string]any)
	if imported["dept"] != "analytics" {
		t.Errorf("imported = %v, want dept=analytics under the mapped key", imported)
	}
	if _, ignored := imported["locale"]; ignored {
		t.Error("an attribute mapped to \"-\" was imported anyway")
	}
}

// email_verified is read as verified only for the exact string "true". Anything
// else is not verified, which is the safe direction: an account that skipped
// verification because an attribute did not parse is a hole.
func TestEmailVerifiedIsConservative(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "1", "yes", "True ", "false", "no"} {
		rec := awsintegration.CognitoUser{
			Username:   "ada",
			Attributes: map[string]string{"email": "ada@example.test", "email_verified": raw},
		}
		user, err := UserFromSource(rec, nil)
		if err != nil {
			t.Fatalf("UserFromSource(%q): %v", raw, err)
		}
		want := raw == "True " // trimmed and case-folded, this is the only "true" above
		if user.IsEmailVerified != want {
			t.Errorf("email_verified %q -> IsEmailVerified %v, want %v", raw, user.IsEmailVerified, want)
		}
	}
}

func TestAttributeMapValidateRejectsAnUnknownTarget(t *testing.T) {
	t.Parallel()
	if err := (AttributeMap{"custom:x": "firstname"}).Validate(); err == nil {
		t.Fatal("a misspelled target was accepted; the whole point of validating before the first page is read")
	}
	if err := (AttributeMap{"custom:x": FieldMetadataPrefix}).Validate(); err == nil {
		t.Fatal("a metadata target with no key was accepted")
	}
	if err := (AttributeMap{"custom:x": FieldMetadataPrefix + "dept", "locale": FieldIgnore}).Validate(); err != nil {
		t.Fatalf("a valid map was rejected: %v", err)
	}
}

func TestNewUserIDMatchesTheCoreShape(t *testing.T) {
	t.Parallel()
	id, err := NewUserID()
	if err != nil {
		t.Fatalf("NewUserID: %v", err)
	}
	// usr_ plus 32 hex characters, which is awesome-go-auth's own newID("usr").
	// A migrated account must not be distinguishable from a registered one by its
	// id: anything that can tell them apart eventually treats them differently.
	if len(id) != len("usr_")+64/2 {
		t.Fatalf("id %q is not the core's shape", id)
	}
	if id[:4] != "usr_" {
		t.Fatalf("id %q does not carry the core's prefix", id)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
