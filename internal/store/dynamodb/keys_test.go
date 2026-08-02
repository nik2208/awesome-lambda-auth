package dynamodb

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// These tests need no endpoint, so a plain checkout still exercises the parts of
// the store that are pure: key construction, identifier validation and the
// timestamp encoding the conditional writes depend on.

// TestTimestampLayoutSortsChronologically is the reason tsLayout pads the
// fraction. DynamoDB compares strings bytewise, so an unpadded fraction makes
// "…:00Z" sort after "…:00.5Z" — which would silently break both the
// "<F>Exp > :now" single-use conditions and the GSI1 session ordering.
func TestTimestampLayoutSortsChronologically(t *testing.T) {
	t.Parallel()
	earlier := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	later := earlier.Add(500 * time.Millisecond)

	if a, b := earlier.Format(time.RFC3339Nano), later.Format(time.RFC3339Nano); !(a > b) {
		t.Fatalf("premise of this test no longer holds: RFC3339Nano gave %q < %q", a, b)
	}
	if a, b := formatTime(earlier), formatTime(later); !(a < b) {
		t.Fatalf("formatTime is not lexicographically ordered: %q >= %q", a, b)
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	t.Parallel()
	want := time.Date(2026, 8, 2, 13, 45, 6, 987654321, time.UTC)
	got, err := parseTime(formatTime(want))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	// Items written before the layout was pinned must still read back (§7 rule 1).
	legacy := want.Format(time.RFC3339Nano)
	got, err = parseTime(legacy)
	if err != nil {
		t.Fatalf("parse legacy %q: %v", legacy, err)
	}
	if !got.Equal(want) {
		t.Fatalf("legacy round trip: got %v, want %v", got, want)
	}

	// A non-UTC input must be normalised, or two clients in different zones would
	// write keys that do not compare.
	zone := time.FixedZone("UTC+5", 5*3600)
	if a, b := formatTime(want), formatTime(want.In(zone)); a != b {
		t.Fatalf("zone leaked into the encoding: %q vs %q", a, b)
	}
}

func TestIdentifierValidation(t *testing.T) {
	t.Parallel()
	// The core's own id shapes must pass, or the store rejects every user it is
	// given (security.go:18-26).
	for _, id := range []string{
		"usr_0123456789abcdef0123456789abcdef",
		"ses_0123456789abcdef0123456789abcdef",
		"acme",
		"tenant-1",
		"tenant.one",
	} {
		if err := checkID("id", id); err != nil {
			t.Fatalf("%q should be accepted: %v", id, err)
		}
	}
	for _, id := range []string{
		"",
		"has#hash",
		"-leading-dash",
		"with space",
		"with/slash",
	} {
		if err := checkID("id", id); !errors.Is(err, ErrInvalidIdentifier) {
			t.Fatalf("%q should be rejected, got %v", id, err)
		}
	}
}

func TestTenantValidationDependsOnMode(t *testing.T) {
	t.Parallel()
	single := &Store{}
	multi := &Store{multiTenant: true}

	if err := single.checkTenant(""); err != nil {
		t.Fatalf("single-tenant mode must accept the empty tenant: %v", err)
	}
	if err := multi.checkTenant(""); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("multi-tenant mode must reject the empty tenant, got %v", err)
	}
	// A non-empty tenant is legal in both modes: awesome-go-auth treats the tenant
	// id as an ordinary value, and rejecting one in single-tenant mode would break
	// every deployment whose tokens already carry a tid claim.
	for _, s := range []*Store{single, multi} {
		if err := s.checkTenant("acme"); err != nil {
			t.Fatalf("tenant \"acme\" rejected: %v", err)
		}
		if err := s.checkTenant("acme#evil"); !errors.Is(err, ErrInvalidIdentifier) {
			t.Fatalf("tenant containing '#' accepted")
		}
	}
}

// TestKeysCannotBeForged states the collision the identifier rules exist to
// prevent, and then shows validation closing it. The key composition itself
// cannot be made unambiguous — USER#a#b#c really is reachable from ("a","b#c")
// and from ("a#b","c") — so the guarantee has to come from refusing the inputs.
func TestKeysCannotBeForged(t *testing.T) {
	t.Parallel()
	if userPK("a", "b#c") != userPK("a#b", "c") {
		t.Fatal("premise changed: the two-segment key is no longer ambiguous, so this rule can be revisited")
	}
	single := &Store{}
	if err := checkID("user id", "b#c"); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("ambiguous user id accepted: %v", err)
	}
	if err := single.checkTenant("a#b"); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("ambiguous tenant id accepted: %v", err)
	}
}

func TestEmailValidation(t *testing.T) {
	t.Parallel()
	if err := checkEmail("user+tag@example.test"); err != nil {
		t.Fatalf("ordinary address rejected: %v", err)
	}
	for _, email := range []string{"", "a@b\nc", strings.Repeat("a", maxEmailKeyLen+1)} {
		if err := checkEmail(email); !errors.Is(err, ErrInvalidEmail) {
			t.Fatalf("%q should be rejected, got %v", email, err)
		}
	}
}

func TestNewValidatesOptions(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, Options{TableName: "t"}); err == nil {
		t.Fatal("a nil client should be refused")
	}
	if _, err := New(struct{ API }{}, Options{}); err == nil {
		t.Fatal("a missing table name should be refused")
	}
	s, err := New(struct{ API }{}, Options{TableName: "t"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if s.index != DefaultIndexName || s.maxSessions != DefaultMaxSessionsPerUser || s.ttlGrace != DefaultSessionTTLGrace {
		t.Fatalf("defaults not applied: %+v", s)
	}
	if !s.consumeOnRead {
		t.Fatal("a zero-value Options must give the atomic single-use behaviour")
	}
}

func TestUpdateExpressionOmitsEmptyClauses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		set, remove []string
		want        string
	}{
		{set: []string{"#a = :a"}, want: "SET #a = :a"},
		{remove: []string{"#a"}, want: "REMOVE #a"},
		{set: []string{"#a = :a", "#b = :b"}, remove: []string{"#c"}, want: "SET #a = :a, #b = :b REMOVE #c"},
	}
	for _, c := range cases {
		if got := updateExpression(c.set, c.remove); got != c.want {
			t.Fatalf("got %q, want %q", got, c.want)
		}
	}
}

func TestItemOmitsAbsentOptionalValues(t *testing.T) {
	t.Parallel()
	it := item{}.s("present", "x").s("absent", "").t("zero", time.Time{}).tp("nil", nil)
	if _, ok := it["present"]; !ok {
		t.Fatal("present value dropped")
	}
	for _, name := range []string{"absent", "zero", "nil"} {
		if _, ok := it[name]; ok {
			// A NULL here would make attribute_not_exists conditions meaningless.
			t.Fatalf("%q was written; absent optional values must be omitted", name)
		}
	}
}

// TestTTLIsEpochSeconds. DynamoDB's TTL reaper reads the attribute as epoch
// seconds and silently ignores a value that is not plausibly one, so a
// millisecond timestamp does not fail — it just means no session, refresh pointer
// or single-use pointer ever expires, and the table grows for ever while replay
// detection keeps resolving tokens that should have been unreachable.
func TestTTLIsEpochSeconds(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	got := item{}.ttl(at)[attrTTL].(*types.AttributeValueMemberN).Value
	if want := strconv.FormatInt(at.Unix(), 10); got != want {
		t.Fatalf("ttl = %q, want %q (seconds, not %d milliseconds)", got, want, at.UnixMilli())
	}
}

func TestCheckVersionRefusesANewerSchema(t *testing.T) {
	t.Parallel()
	current := item{}.stamp(typeUser)
	if err := checkVersion(current, typeUser); err != nil {
		t.Fatalf("current version rejected: %v", err)
	}
	future := item{}.stamp(typeUser).n(attrVer, schemaVersion+1)
	if err := checkVersion(future, typeUser); err == nil {
		t.Fatal("an item from a newer schema version must not be decoded silently")
	}
}
