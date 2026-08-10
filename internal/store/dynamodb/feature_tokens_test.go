package dynamodb

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	auth "github.com/nik2208/awesome-go-auth"
)

// The five single-use families are one implementation, so they are one test
// table. Every case below runs against all of them, which is the property that
// makes reviewing one family enough: a behaviour that held only for reset would
// fail here for the other four.
type familyCase struct {
	name   string
	family tokenFamily

	// issue, consume and clear are the interface methods, bound so the shape is
	// uniform. consume's userID and tenantID are ignored by the pointer families,
	// which resolve them from the pointer item — that asymmetry is the only
	// difference between SMS and the rest.
	issue   func(context.Context, *Store, string, string, string, time.Time) error
	consume func(context.Context, *Store, string, string, string) (auth.User, error)
	clear   func(context.Context, *Store, string, string) error

	// storedHash and storedExpiry read back the two fields the core checks on the
	// user a consume returns (service.go:343, :394, :435, :473).
	storedHash   func(auth.User) string
	storedExpiry func(auth.User) *time.Time
}

func familyCases() []familyCase {
	return []familyCase{
		{
			name:   "reset",
			family: familyReset,
			issue: func(ctx context.Context, s *Store, uid, tid, hash string, exp time.Time) error {
				return s.UpdateResetToken(ctx, uid, tid, hash, exp)
			},
			consume: func(ctx context.Context, s *Store, _, _, hash string) (auth.User, error) {
				return s.GetUserByResetTokenHash(ctx, hash)
			},
			clear:        func(ctx context.Context, s *Store, uid, tid string) error { return s.ClearResetToken(ctx, uid, tid) },
			storedHash:   func(u auth.User) string { return u.ResetTokenHash },
			storedExpiry: func(u auth.User) *time.Time { return u.ResetTokenExpiresAt },
		},
		{
			name:   "magic",
			family: familyMagic,
			issue: func(ctx context.Context, s *Store, uid, tid, hash string, exp time.Time) error {
				return s.UpdateMagicLinkToken(ctx, uid, tid, hash, exp)
			},
			consume: func(ctx context.Context, s *Store, _, _, hash string) (auth.User, error) {
				return s.GetUserByMagicLinkTokenHash(ctx, hash)
			},
			clear: func(ctx context.Context, s *Store, uid, tid string) error {
				return s.ClearMagicLinkToken(ctx, uid, tid)
			},
			storedHash:   func(u auth.User) string { return u.MagicLinkTokenHash },
			storedExpiry: func(u auth.User) *time.Time { return u.MagicLinkTokenExpiresAt },
		},
		{
			name:   "verify",
			family: familyVerify,
			issue: func(ctx context.Context, s *Store, uid, tid, hash string, exp time.Time) error {
				return s.UpdateEmailVerificationToken(ctx, uid, tid, hash, exp)
			},
			consume: func(ctx context.Context, s *Store, _, _, hash string) (auth.User, error) {
				return s.GetUserByEmailVerificationTokenHash(ctx, hash)
			},
			clear: func(ctx context.Context, s *Store, uid, tid string) error {
				return s.ClearEmailVerificationToken(ctx, uid, tid)
			},
			storedHash:   func(u auth.User) string { return u.EmailVerificationTokenHash },
			storedExpiry: func(u auth.User) *time.Time { return u.EmailVerificationTokenExpiry },
		},
		{
			name:   "echg",
			family: familyEchg,
			// A fresh pending address per call. A real retry would repeat one, so
			// varying it is the harder case: the pointer's ownership condition, not
			// the address, is what has to let the call through.
			issue: func(ctx context.Context, s *Store, uid, tid, hash string, exp time.Time) error {
				return s.UpdateEmailChangeToken(ctx, uid, tid, uniqueEmail("pending"), hash, exp)
			},
			consume: func(ctx context.Context, s *Store, _, _, hash string) (auth.User, error) {
				return s.GetUserByEmailChangeTokenHash(ctx, hash)
			},
			clear: func(ctx context.Context, s *Store, uid, tid string) error {
				return s.ClearEmailChangeToken(ctx, uid, tid)
			},
			storedHash:   func(u auth.User) string { return u.EmailChangeTokenHash },
			storedExpiry: func(u auth.User) *time.Time { return u.EmailChangeTokenExpiry },
		},
		{
			name:   "sms",
			family: familySMS,
			issue: func(ctx context.Context, s *Store, uid, tid, hash string, exp time.Time) error {
				return s.UpdateSMSCode(ctx, uid, tid, hash, exp)
			},
			consume: func(ctx context.Context, s *Store, uid, tid, hash string) (auth.User, error) {
				return s.GetUserBySMSCodeHash(ctx, uid, tid, hash)
			},
			clear:        func(ctx context.Context, s *Store, uid, tid string) error { return s.ClearSMSCode(ctx, uid, tid) },
			storedHash:   func(u auth.User) string { return u.SMSCodeHash },
			storedExpiry: func(u auth.User) *time.Time { return u.SMSCodeExpiresAt },
		},
	}
}

// TestSingleUseFamilyTableIsConsistent needs no database. The most likely defect
// in a table like this one is a copy-paste — two families sharing a profile
// attribute, or one missing its error — and every such mistake is silent: the
// wrong attribute still reads and writes, it just consumes somebody else's token.
func TestSingleUseFamilyTableIsConsistent(t *testing.T) {
	t.Parallel()
	seen := map[string]string{}
	for _, c := range familyCases() {
		f := c.family
		if f.name == "" || f.hashAttr == "" || f.expAttr == "" {
			t.Fatalf("%s: incomplete family %+v", c.name, f)
		}
		if f.invalidErr == nil {
			t.Fatalf("%s: no invalidErr, so a lost condition would surface as nil", c.name)
		}
		if f.hasPointer() && !strings.HasSuffix(f.pkPrefix, keySep) {
			t.Fatalf("%s: pkPrefix %q must end in %q or the hash runs into the prefix", c.name, f.pkPrefix, keySep)
		}
		if len(f.extraIssueAttrs) != len(f.extraClearAttrs) {
			t.Fatalf("%s: issues %v but clears %v; an attribute written with the token must go with it",
				c.name, f.extraIssueAttrs, f.extraClearAttrs)
		}
		for _, attr := range []string{f.hashAttr, f.expAttr, f.pkPrefix} {
			if attr == "" {
				continue
			}
			if prev, dup := seen[attr]; dup {
				t.Fatalf("%s and %s both use %q", c.name, prev, attr)
			}
			seen[attr] = c.name
		}
	}
	if len(pointerFamilies) != 4 {
		t.Fatalf("pointerFamilies has %d entries, want the four pointer-backed families", len(pointerFamilies))
	}
}

// TestSingleUseFamiliesIssueConsumeClear is the whole lifecycle, per family:
// issue writes the profile and (where there is one) the pointer, the lookup
// consumes exactly once, and clear is an idempotent no-op afterwards.
func TestSingleUseFamiliesIssueConsumeClear(t *testing.T) {
	t.Parallel()
	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			store, client := newStore(t)
			ctx := context.Background()
			u := newUser(t, store, "acme")

			hash := hashOf(uniqueID(c.name))
			expiry := time.Now().Add(time.Hour).UTC()
			if err := c.issue(ctx, store, u.ID, "acme", hash, expiry); err != nil {
				t.Fatalf("issue: %v", err)
			}

			profile := rawItem(t, client, store.table, userPK("acme", u.ID), skProfile)
			if got := getS(profile, c.family.hashAttr); got != hash {
				t.Fatalf("profile %s = %q, want %q", c.family.hashAttr, got, hash)
			}
			// The stored expiry has to be the fixed-width layout, because the
			// consume condition compares it to :now as a string.
			if got, want := getS(profile, c.family.expAttr), formatTime(expiry); got != want {
				t.Fatalf("profile %s = %q, want %q", c.family.expAttr, got, want)
			}
			if c.family.hasPointer() {
				assertPointer(t, client, store.table, c.family, hash, u.ID, "acme", expiry)
			}

			got, err := c.consume(ctx, store, u.ID, "acme", hash)
			if err != nil {
				t.Fatalf("consume: %v", err)
			}
			if got.ID != u.ID {
				t.Fatalf("resolved to %q, want %q", got.ID, u.ID)
			}
			// The pre-image must carry the token state: the core re-checks the
			// expiry on the user this method returns, and a nil expiry is an
			// invalid token there.
			if h := c.storedHash(got); h != hash {
				t.Fatalf("returned hash = %q, want %q", h, hash)
			}
			exp := c.storedExpiry(got)
			if exp == nil || !exp.Equal(expiry) {
				t.Fatalf("returned expiry = %v, want %v", exp, expiry)
			}

			// Consumed means gone from the item, not merely refused on the next read.
			after := rawItem(t, client, store.table, userPK("acme", u.ID), skProfile)
			if getS(after, c.family.hashAttr) != "" || getS(after, c.family.expAttr) != "" {
				t.Fatalf("consume left %s/%s behind: %v", c.family.hashAttr, c.family.expAttr, after)
			}

			if _, err := c.consume(ctx, store, u.ID, "acme", hash); !errors.Is(err, c.family.invalidErr) {
				t.Fatalf("second consume: err = %v, want %v", err, c.family.invalidErr)
			}

			// Clear runs after the consume on every one of these flows, so it must
			// not care that the attribute has already gone.
			for i := range 2 {
				if err := c.clear(ctx, store, u.ID, "acme"); err != nil {
					t.Fatalf("clear %d: %v", i, err)
				}
			}
			if err := c.clear(ctx, store, uniqueID("usr"), "acme"); !errors.Is(err, ErrUserNotFound) {
				t.Fatalf("clear for a missing user: err = %v, want ErrUserNotFound", err)
			}
		})
	}
}

// assertPointer checks the pointer item, including the one attribute whose unit
// nothing else can catch.
func assertPointer(t *testing.T, client *awsddb.Client, table string, f tokenFamily, hash, userID, tenantID string, expiry time.Time) {
	t.Helper()
	ptr := rawItem(t, client, table, f.pk(hash), skToken)
	if len(ptr) == 0 {
		t.Fatal("pointer item missing; a tenant-less lookup has nothing to resolve")
	}
	if got := getS(ptr, attrFamily); got != f.name {
		t.Errorf("pointer family = %q, want %q", got, f.name)
	}
	if got := getS(ptr, attrUserID); got != userID {
		t.Errorf("pointer userId = %q, want %q", got, userID)
	}
	// The tenant a downstream key gets built from comes from here, so this is the
	// isolation guarantee for a capability-keyed lookup, not bookkeeping.
	if got := getS(ptr, attrTenantID); got != tenantID {
		t.Errorf("pointer tenantId = %q, want %q", got, tenantID)
	}

	// TTL is epoch SECONDS. Read raw, not asserted against the code that wrote
	// it: DynamoDB silently ignores an implausible TTL value, so milliseconds
	// here would mean these pointers never expire and nothing would ever say so.
	ttl := getN(ptr, attrTTL)
	if ttl != expiry.Unix() {
		t.Errorf("pointer ttl = %d, want %d (epoch seconds; %d would be milliseconds)",
			ttl, expiry.Unix(), expiry.UnixMilli())
	}
	// Belt and braces on the magnitude, so a future change that multiplies by
	// 1000 fails here instead of quietly disabling expiry: seconds stay well
	// under 1e12 until the year 33658.
	if ttl > 1e12 {
		t.Errorf("pointer ttl = %d is too large to be epoch seconds", ttl)
	}
}

// TestSingleUseFamiliesRefuseAnExpiredValue is the TTL-is-not-a-boundary case.
// DynamoDB's reaper lags by up to hours, so an expired-but-present item must be
// refused by the condition, in code, on every family.
func TestSingleUseFamiliesRefuseAnExpiredValue(t *testing.T) {
	t.Parallel()
	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			store, client := newStore(t)
			ctx := context.Background()
			u := newUser(t, store, "acme")

			hash := hashOf(uniqueID("stale"))
			if err := c.issue(ctx, store, u.ID, "acme", hash, time.Now().Add(-time.Minute)); err != nil {
				t.Fatalf("issue: %v", err)
			}
			// The item is still there — that is the point.
			if c.family.hasPointer() {
				if len(rawItem(t, client, store.table, c.family.pk(hash), skToken)) == 0 {
					t.Fatal("pointer already gone; the test is not exercising a late item")
				}
			}
			if _, err := c.consume(ctx, store, u.ID, "acme", hash); !errors.Is(err, c.family.invalidErr) {
				t.Fatalf("expired: err = %v, want %v", err, c.family.invalidErr)
			}
		})
	}
}

// TestSingleUseFamiliesReissueInvalidatesThePrevious matches MemoryUserStore,
// which deletes the old hash from its index when a new token is issued.
func TestSingleUseFamiliesReissueInvalidatesThePrevious(t *testing.T) {
	t.Parallel()
	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			store, _ := newStore(t)
			ctx := context.Background()
			u := newUser(t, store, "acme")

			old, fresh := hashOf(uniqueID("first")), hashOf(uniqueID("second"))
			expiry := time.Now().Add(time.Hour)
			if err := c.issue(ctx, store, u.ID, "acme", old, expiry); err != nil {
				t.Fatalf("issue first: %v", err)
			}
			if err := c.issue(ctx, store, u.ID, "acme", fresh, expiry); err != nil {
				t.Fatalf("issue second: %v", err)
			}
			// The superseded pointer still resolves to the user — it is a hint,
			// reaped by TTL — but the profile's hash has moved on, so the consume
			// condition cannot match it.
			if _, err := c.consume(ctx, store, u.ID, "acme", old); !errors.Is(err, c.family.invalidErr) {
				t.Fatalf("superseded: err = %v, want %v", err, c.family.invalidErr)
			}
			if _, err := c.consume(ctx, store, u.ID, "acme", fresh); err != nil {
				t.Fatalf("current: %v", err)
			}
		})
	}
}

func TestSingleUseFamiliesRejectUnknownValues(t *testing.T) {
	t.Parallel()
	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			store, _ := newStore(t)
			ctx := context.Background()
			u := newUser(t, store, "acme")

			for _, hash := range []string{"", hashOf("never-issued")} {
				if _, err := c.consume(ctx, store, u.ID, "acme", hash); !errors.Is(err, c.family.invalidErr) {
					t.Fatalf("hash %q: err = %v, want %v", hash, err, c.family.invalidErr)
				}
			}
		})
	}
}

// TestSingleUseFamiliesIssueForAMissingUser: UpdateItem creates an absent item,
// so without attribute_exists(PK) this would manufacture a profile-shaped item
// holding nothing but a token.
func TestSingleUseFamiliesIssueForAMissingUser(t *testing.T) {
	t.Parallel()
	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			store, client := newStore(t)
			ctx := context.Background()

			ghost := uniqueID("usr")
			err := c.issue(ctx, store, ghost, "acme", hashOf("x"), time.Now().Add(time.Hour))
			if !errors.Is(err, ErrUserNotFound) {
				t.Fatalf("err = %v, want ErrUserNotFound", err)
			}
			mustNotExist(t, client, store.table, userPK("acme", ghost), skProfile)
		})
	}
}

// TestSingleUseFamiliesIssueIsRetrySafe: a bare attribute_not_exists on the
// pointer would turn a transient blip into a permanent failure, because the
// pointer the first attempt wrote is indistinguishable from a collision.
func TestSingleUseFamiliesIssueIsRetrySafe(t *testing.T) {
	t.Parallel()
	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			store, _ := newStore(t)
			ctx := context.Background()
			u := newUser(t, store, "acme")

			hash := hashOf(uniqueID("retried"))
			expiry := time.Now().Add(time.Hour)
			for i := range 3 {
				if err := c.issue(ctx, store, u.ID, "acme", hash, expiry); err != nil {
					t.Fatalf("attempt %d: %v", i, err)
				}
			}
			if _, err := c.consume(ctx, store, u.ID, "acme", hash); err != nil {
				t.Fatalf("consume after retries: %v", err)
			}
		})
	}
}

// TestPointerOwnershipIsEnforced: the ownership clause lets a caller reclaim its
// own pointer, which is what makes a retry safe — but a *different* owner behind
// the same hash is a sha256 collision and must stay loud rather than silently
// re-point one user's token at another's profile.
func TestPointerOwnershipIsEnforced(t *testing.T) {
	t.Parallel()
	for _, f := range pointerFamilies {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			store, client := newStore(t)
			ctx := context.Background()
			first := newUser(t, store, "acme")
			second := newUser(t, store, "acme")

			hash := hashOf(uniqueID("collision"))
			expiry := time.Now().Add(time.Hour)
			if err := store.issueSingleUseToken(ctx, f, first.ID, "acme", hash, expiry, extrasFor(f)...); err != nil {
				t.Fatalf("issue for the first owner: %v", err)
			}
			err := store.issueSingleUseToken(ctx, f, second.ID, "acme", hash, expiry, extrasFor(f)...)
			if err == nil {
				t.Fatal("a second owner claimed the same pointer; one user's token now resolves to another's profile")
			}
			if errors.Is(err, ErrUserNotFound) {
				t.Fatalf("collision reported as a missing user: %v", err)
			}
			// The first owner's pointer is untouched.
			if got := getS(rawItem(t, client, store.table, f.pk(hash), skToken), attrUserID); got != first.ID {
				t.Fatalf("pointer userId = %q, want %q", got, first.ID)
			}
		})
	}
}

// TestPointerTenantIsNotTakenFromTheCaller: the same hash issued in two tenants
// is the same partition key, so the ownership condition has to compare the tenant
// too. Otherwise tenant B could overwrite tenant A's pointer and redirect the
// lookup into its own partition.
func TestPointerTenantIsNotTakenFromTheCaller(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	acme := newUser(t, store, "acme")
	other := newUser(t, store, "other")

	hash := hashOf(uniqueID("cross-tenant"))
	expiry := time.Now().Add(time.Hour)
	if err := store.UpdateMagicLinkToken(ctx, acme.ID, "acme", hash, expiry); err != nil {
		t.Fatalf("issue in acme: %v", err)
	}
	if err := store.UpdateMagicLinkToken(ctx, other.ID, "other", hash, expiry); err == nil {
		t.Fatal("a second tenant claimed the same pointer")
	}
	got, err := store.GetUserByMagicLinkTokenHash(ctx, hash)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.ID != acme.ID || got.TenantID != "acme" {
		t.Fatalf("resolved to %s/%s, want %s/acme", got.TenantID, got.ID, acme.ID)
	}
}

// TestSMSCodeIsScopedToItsUserAndTenant. SMS has no pointer, so the user key comes
// straight from the caller — which makes it the one family where a wrong tenant is
// expressible at all. It must find nothing rather than match.
func TestSMSCodeIsScopedToItsUserAndTenant(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	mine := newUser(t, store, "acme")
	theirs := newUser(t, store, "acme")

	code := hashOf("123456")
	if err := store.UpdateSMSCode(ctx, mine.ID, "acme", code, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := store.GetUserBySMSCodeHash(ctx, theirs.ID, "acme", code); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("another user's code: err = %v, want ErrInvalidCode", err)
	}
	if _, err := store.GetUserBySMSCodeHash(ctx, mine.ID, "other", code); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("wrong tenant: err = %v, want ErrInvalidCode", err)
	}
	// Neither attempt burned it.
	if _, err := store.GetUserBySMSCodeHash(ctx, mine.ID, "acme", code); err != nil {
		t.Fatalf("the owner's code was burned by someone else's attempt: %v", err)
	}
}

// TestAWrongSMSCodeDoesNotBurnTheStoredOne preserves the reference's behaviour:
// there is no attempt counter, the user retries until expiry, and a mistyped digit
// must not cost them the code.
func TestAWrongSMSCodeDoesNotBurnTheStoredOne(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	right := hashOf("424242")
	if err := store.UpdateSMSCode(ctx, u.ID, "acme", right, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	for _, wrong := range []string{hashOf("000000"), hashOf("424243"), hashOf("999999")} {
		if _, err := store.GetUserBySMSCodeHash(ctx, u.ID, "acme", wrong); !errors.Is(err, auth.ErrInvalidCode) {
			t.Fatalf("wrong code: err = %v, want ErrInvalidCode", err)
		}
	}
	if _, err := store.GetUserBySMSCodeHash(ctx, u.ID, "acme", right); err != nil {
		t.Fatalf("the right code after three wrong ones: %v", err)
	}
}

func TestMarkEmailVerified(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	for _, want := range []bool{false, true, true} {
		if err := store.MarkEmailVerified(ctx, u.ID, "acme", want); err != nil {
			t.Fatalf("mark %v: %v", want, err)
		}
		got, err := store.GetUserByID(ctx, u.ID, "acme")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.IsEmailVerified != want {
			t.Fatalf("isEmailVerified = %v, want %v", got.IsEmailVerified, want)
		}
	}
	if err := store.MarkEmailVerified(ctx, u.ID, "other", true); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("cross-tenant: err = %v, want ErrUserNotFound", err)
	}
	if err := store.MarkEmailVerified(ctx, uniqueID("usr"), "acme", true); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user: err = %v, want ErrUserNotFound", err)
	}
}

// TestEmailChangeCarriesThePendingAddressThroughTheConsume is the whole flow, and
// the reason the consume removes only the hash and the expiry: ApplyEmailChange
// carries no address of its own and reads the pending one off the profile *after*
// the token has been burned.
func TestEmailChangeCarriesThePendingAddressThroughTheConsume(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")
	oldEmail := u.Email
	newEmail := uniqueEmail("moved")

	hash := hashOf(uniqueID("echg"))
	if err := store.UpdateEmailChangeToken(ctx, u.ID, "acme", strings.ToUpper(newEmail), hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Normalized on the way in, as the core does, so the uniqueness key this
	// computes is the one login will compute.
	if got := getS(rawItem(t, client, store.table, userPK("acme", u.ID), skProfile), attrPendingEmail); got != newEmail {
		t.Fatalf("pendingEmail = %q, want the normalized %q", got, newEmail)
	}

	consumed, err := store.GetUserByEmailChangeTokenHash(ctx, hash)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if consumed.PendingEmail != newEmail {
		t.Fatalf("consumed user PendingEmail = %q, want %q", consumed.PendingEmail, newEmail)
	}
	// Still on the item: ApplyEmailChange has not run yet.
	if got := getS(rawItem(t, client, store.table, userPK("acme", u.ID), skProfile), attrPendingEmail); got != newEmail {
		t.Fatalf("consume removed pendingEmail; ApplyEmailChange has nothing to promote (got %q)", got)
	}

	if err := store.ApplyEmailChange(ctx, u.ID, "acme"); err != nil {
		t.Fatalf("apply: %v", err)
	}

	got, err := store.GetUserByID(ctx, u.ID, "acme")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Email != newEmail {
		t.Fatalf("email = %q, want %q", got.Email, newEmail)
	}
	if got.PendingEmail != "" {
		t.Fatalf("pendingEmail = %q, want it gone", got.PendingEmail)
	}
	// The uniqueness item moved with it, or a re-registration of the old address
	// would fail and login on the new one would not resolve.
	if _, err := store.GetUserByEmail(ctx, newEmail, "acme"); err != nil {
		t.Fatalf("resolve by the new address: %v", err)
	}
	if _, err := store.GetUserByEmail(ctx, oldEmail, "acme"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("old address still resolves: err = %v, want ErrUserNotFound", err)
	}
	mustNotExist(t, client, store.table, emailPK("acme", oldEmail), skEmail)

	// Clear afterwards is a no-op on an address that has already been promoted.
	if err := store.ClearEmailChangeToken(ctx, u.ID, "acme"); err != nil {
		t.Fatalf("clear: %v", err)
	}
}

// TestClearEmailChangeTokenDropsThePendingAddress: MemoryUserStore clears
// PendingEmail alongside the token (memory_store.go:395), so an abandoned request
// must not leave an address the next ApplyEmailChange could promote.
func TestClearEmailChangeTokenDropsThePendingAddress(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	if err := store.UpdateEmailChangeToken(ctx, u.ID, "acme", uniqueEmail("abandoned"), hashOf(uniqueID("echg")), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := store.ClearEmailChangeToken(ctx, u.ID, "acme"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	got, err := store.GetUserByID(ctx, u.ID, "acme")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.PendingEmail != "" || got.EmailChangeTokenHash != "" {
		t.Fatalf("clear left state behind: pendingEmail=%q hash=%q", got.PendingEmail, got.EmailChangeTokenHash)
	}
	if err := store.ApplyEmailChange(ctx, u.ID, "acme"); !errors.Is(err, ErrNoPendingEmailChange) {
		t.Fatalf("apply after clear: err = %v, want ErrNoPendingEmailChange", err)
	}
}

func TestApplyEmailChangeRefusesATakenAddress(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	mover := newUser(t, store, "acme")
	squatter := newUser(t, store, "acme")

	if err := store.UpdateEmailChangeToken(ctx, mover.ID, "acme", squatter.Email, hashOf(uniqueID("echg")), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := store.ApplyEmailChange(ctx, mover.ID, "acme"); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("err = %v, want ErrUserExists", err)
	}
	// Nothing moved: the transaction is all-or-nothing, so the squatter still owns
	// the address and the mover still owns theirs.
	if got, err := store.GetUserByEmail(ctx, squatter.Email, "acme"); err != nil || got.ID != squatter.ID {
		t.Fatalf("squatter's address now resolves to %v (err %v)", got.ID, err)
	}
	if got, err := store.GetUserByEmail(ctx, mover.Email, "acme"); err != nil || got.ID != mover.ID {
		t.Fatalf("mover lost their own address: %v (err %v)", got.ID, err)
	}
}

// TestApplyEmailChangeToTheCurrentAddress. The reference reaches ErrUserExists
// here because old and new hash to one map key; this store must reach the same
// answer without handing DynamoDB a transaction that touches one item twice,
// which it rejects outright.
func TestApplyEmailChangeToTheCurrentAddress(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	if err := store.UpdateEmailChangeToken(ctx, u.ID, "acme", u.Email, hashOf(uniqueID("echg")), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := store.ApplyEmailChange(ctx, u.ID, "acme"); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("err = %v, want ErrUserExists", err)
	}
	if got, err := store.GetUserByEmail(ctx, u.Email, "acme"); err != nil || got.ID != u.ID {
		t.Fatalf("the address stopped resolving: %v (err %v)", got.ID, err)
	}
}

func TestApplyEmailChangeForAMissingUser(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if err := store.ApplyEmailChange(ctx, uniqueID("usr"), "acme"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
	u := newUser(t, store, "acme")
	if err := store.ApplyEmailChange(ctx, u.ID, "other"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("cross-tenant: err = %v, want ErrUserNotFound", err)
	}
}

// beforeTransactAPI runs a hook once, immediately before the first transaction
// reaches DynamoDB. It exists to open the window between ApplyEmailChange's read
// and its write, which is the only way to reach the stale branch deterministically
// — DynamoDB Local serialises real concurrency.
type beforeTransactAPI struct {
	API
	once sync.Once
	hook func()
}

func (a *beforeTransactAPI) TransactWriteItems(ctx context.Context, in *awsddb.TransactWriteItemsInput, optFns ...func(*awsddb.Options)) (*awsddb.TransactWriteItemsOutput, error) {
	a.once.Do(func() {
		if a.hook != nil {
			a.hook()
		}
	})
	return a.API.TransactWriteItems(ctx, in, optFns...)
}

// TestApplyEmailChangeRefusesAStalePendingAddress is the reason the profile update
// is conditional on both the current and the pending address rather than being a
// blind write of what the read saw.
//
// The read has to happen — the method carries no address — but it must not be
// what decides. If the pending address moves in between, the change being
// confirmed is no longer the pending one and applying it would promote an address
// whose token was superseded.
func TestApplyEmailChangeRefusesAStalePendingAddress(t *testing.T) {
	t.Parallel()
	base, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, base, "acme")

	firstTarget, secondTarget := uniqueEmail("first"), uniqueEmail("second")
	if err := base.UpdateEmailChangeToken(ctx, u.ID, "acme", firstTarget, hashOf(uniqueID("echg")), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue: %v", err)
	}

	hooked := &beforeTransactAPI{API: client, hook: func() {
		// A second request arrives after the read and before the write, pointing the
		// pending address somewhere else.
		if err := base.UpdateEmailChangeToken(ctx, u.ID, "acme", secondTarget, hashOf(uniqueID("echg2")), time.Now().Add(time.Hour)); err != nil {
			t.Errorf("re-point pendingEmail: %v", err)
		}
	}}
	store, err := New(hooked, Options{TableName: base.table, Logger: base.log})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	if err := store.ApplyEmailChange(ctx, u.ID, "acme"); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("stale apply: err = %v, want ErrInvalidToken", err)
	}
	got, err := base.GetUserByID(ctx, u.ID, "acme")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Email != u.Email {
		t.Fatalf("email = %q; a stale pending address was applied", got.Email)
	}
	if got.PendingEmail != secondTarget {
		t.Fatalf("pendingEmail = %q, want %q", got.PendingEmail, secondTarget)
	}
	// The refused transaction wrote nothing, so neither target owns a uniqueness
	// item.
	mustNotExist(t, client, store.table, emailPK("acme", firstTarget), skEmail)
	mustNotExist(t, client, store.table, emailPK("acme", secondTarget), skEmail)
}

// TestNonAtomicModeAppliesToEveryFamily: the parity escape hatch is documented as
// restoring the reference's read-then-clear, and it has to do that uniformly.
// A family that stayed atomic under it would make strict-parity testing lie.
func TestNonAtomicModeAppliesToEveryFamily(t *testing.T) {
	t.Parallel()
	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			store, _ := newStore(t, func(o *Options) { o.NonAtomicSingleUseTokens = true })
			ctx := context.Background()
			u := newUser(t, store, "acme")

			hash := hashOf(uniqueID("parity"))
			if err := c.issue(ctx, store, u.ID, "acme", hash, time.Now().Add(time.Hour)); err != nil {
				t.Fatalf("issue: %v", err)
			}
			for i := range 2 {
				if _, err := c.consume(ctx, store, u.ID, "acme", hash); err != nil {
					t.Fatalf("lookup %d: %v", i, err)
				}
			}
			if err := c.clear(ctx, store, u.ID, "acme"); err != nil {
				t.Fatalf("clear: %v", err)
			}
			if _, err := c.consume(ctx, store, u.ID, "acme", hash); !errors.Is(err, c.family.invalidErr) {
				t.Fatalf("after clear: err = %v, want %v", err, c.family.invalidErr)
			}
		})
	}
}

// extrasFor supplies whatever a family's issue path requires beyond the hash, for
// the tests that call the primitive directly.
func extrasFor(f tokenFamily) []tokenExtra {
	extras := make([]tokenExtra, 0, len(f.extraIssueAttrs))
	for _, attr := range f.extraIssueAttrs {
		extras = append(extras, tokenExtra{attr: attr, value: uniqueEmail("extra")})
	}
	return extras
}
