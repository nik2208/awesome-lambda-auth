package dynamodb

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// The three key namespaces the core composes (oauth_wire.go:417-426), spelled out
// as the literals the core produces rather than derived from the store's own
// table — otherwise the test would agree with the code by construction and prove
// nothing about the core.
const (
	stateKeyOAuthState = "oauth-state:"
	stateKeyLinkToken  = "link-token:"
	stateKeyConflict   = "pending-link:"
)

func oauthStateKey() string { return stateKeyOAuthState + randomHex(16) }
func linkTokenKey() string  { return stateKeyLinkToken + hashOf(randomHex(32)) }

// conflictKey reproduces pendingLinkKey(email, provider): the reference's
// (email, provider) stash key. Note what it is *not* — high-entropy — which is
// the reason it is not consumed on read.
func conflictKey(email, provider string) string {
	return stateKeyConflict + strings.ToLower(email) + "|" + provider
}

// testClock is a settable clock for the expiry paths. The pending-link deadline is
// computed by the store from the ttl argument, so the only way to reach it is to
// move time forward; a real sleep would put a minute into the suite.
type testClock struct{ nanos atomic.Int64 }

func newTestClock() *testClock {
	c := &testClock{}
	c.nanos.Store(time.Now().UnixNano())
	return c
}

func (c *testClock) now() time.Time          { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *testClock) advance(d time.Duration) { c.nanos.Add(int64(d)) }

func sampleMeta() auth.OAuthPendingMeta {
	return auth.OAuthPendingMeta{
		Provider:          "google",
		RedirectURL:       "https://app.example.test",
		TenantID:          "acme",
		UserID:            uniqueID("usr"),
		Email:             "conflict@example.test",
		ProviderAccountID: "sub-" + randomHex(8),
		ExpiresAt:         time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond),
	}
}

// TestPendingLinkSingleUseTableMatchesTheCoreNamespaces is a pure unit test, and
// the one that catches the most likely defect in a prefix-driven decision: a
// namespace classified the wrong way round. Getting it wrong is silent — the
// entry still reads and writes, it just gets consumed when it should not be, or
// survives when it should not.
func TestPendingLinkSingleUseTableMatchesTheCoreNamespaces(t *testing.T) {
	t.Parallel()

	// The two the core writes and spends once: the OAuth state nonce
	// (oauth_wire.go:485, read at :530) and the account-link token (:710, read at
	// :765).
	for _, state := range []string{oauthStateKey(), linkTokenKey()} {
		if !pendingLinkIsSingleUse(state) {
			t.Errorf("%q is not classified single-use, so a nonce or a link token would be replayable", state)
		}
	}
	// The conflict stash, which LinkRequest reads to resolve an identity
	// (oauth_wire.go:689) and LinkVerify deletes only after the link is written
	// (:804). Consuming it would make a second POST /link-request answer 401.
	if pendingLinkIsSingleUse(conflictKey("someone@example.test", "acme")) {
		t.Error("the conflict stash is classified single-use; a retried POST /link-request would answer UNAUTHORIZED")
	}
	// An unknown namespace defaults to re-readable, which is exactly
	// MemoryPendingLinks' behaviour.
	if pendingLinkIsSingleUse("something-new:abc") {
		t.Error("an unrecognised namespace is classified single-use; a new re-readable kind would break silently")
	}
}

// TestPendingLinkConflictStashIsNotConsumed is the same property against the real
// table.
func TestPendingLinkConflictStashIsNotConsumed(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	pending := store.PendingLinks()
	ctx := context.Background()

	key := conflictKey("conflict@example.test", "acme")
	meta := sampleMeta()
	if err := pending.Save(ctx, key, meta, time.Hour); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for i := range 3 {
		got, err := pending.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		if got.ProviderAccountID != meta.ProviderAccountID {
			t.Errorf("Get %d = %+v, want ProviderAccountID %q", i, got, meta.ProviderAccountID)
		}
	}
	if err := pending.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := pending.Get(ctx, key); !errors.Is(err, ErrPendingLinkNotFound) {
		t.Errorf("Get after Delete = %v, want ErrPendingLinkNotFound", err)
	}
}

// TestPendingLinkSingleUseIsConsumedOnRead: the read is the consume, for the same
// reason it is in tokens.go — the core discards Delete's error, so a conditional
// Delete would prove one winner to nobody.
func TestPendingLinkSingleUseIsConsumedOnRead(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	pending := store.PendingLinks()
	ctx := context.Background()

	for _, key := range []string{oauthStateKey(), linkTokenKey()} {
		meta := sampleMeta()
		if err := pending.Save(ctx, key, meta, time.Hour); err != nil {
			t.Fatalf("Save %s: %v", key, err)
		}
		got, err := pending.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get %s: %v", key, err)
		}
		if got.UserID != meta.UserID || got.TenantID != meta.TenantID {
			t.Errorf("Get %s = %+v, want UserID %q TenantID %q", key, got, meta.UserID, meta.TenantID)
		}
		// The item is gone, not merely flagged.
		mustNotExist(t, client, store.table, pendingLinkPK(key), skPendingLink)
		if _, err := pending.Get(ctx, key); !errors.Is(err, ErrPendingLinkNotFound) {
			t.Errorf("second Get %s = %v, want ErrPendingLinkNotFound", key, err)
		}
		// And the Delete the core issues afterwards is an idempotent no-op.
		if err := pending.Delete(ctx, key); err != nil {
			t.Errorf("Delete after a consuming Get %s = %v, want nil", key, err)
		}
	}
}

// TestPendingLinkMetaRoundTrips checks every field of OAuthPendingMeta, including
// ExpiresAt — which is the *caller's* deadline and is documented as existing so a
// consumer can enforce it itself (oauth.go:55-57), so returning the store's own
// deadline in its place would be a silent substitution.
func TestPendingLinkMetaRoundTrips(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	pending := store.PendingLinks()
	ctx := context.Background()

	key := conflictKey("round@example.test", "google")
	meta := sampleMeta()
	if err := pending.Save(ctx, key, meta, time.Hour); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := pending.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Provider != meta.Provider || got.RedirectURL != meta.RedirectURL ||
		got.TenantID != meta.TenantID || got.UserID != meta.UserID ||
		got.Email != meta.Email || got.ProviderAccountID != meta.ProviderAccountID {
		t.Errorf("Get = %+v, want %+v", got, meta)
	}
	if !got.ExpiresAt.Equal(meta.ExpiresAt) {
		t.Errorf("ExpiresAt = %s, want the caller's own %s", got.ExpiresAt, meta.ExpiresAt)
	}
}

// TestPendingLinkTTLIsEpochSeconds reads the raw item, because a millisecond ttl
// is not an error DynamoDB reports — it just means the item never expires, and
// nothing tells you.
func TestPendingLinkTTLIsEpochSeconds(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	store, client := newStore(t, func(o *Options) { o.Now = clock.now })
	ctx := context.Background()

	key := linkTokenKey()
	const ttl = 90 * time.Minute
	before := clock.now()
	if err := store.PendingLinks().Save(ctx, key, sampleMeta(), ttl); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw := rawItem(t, client, store.table, pendingLinkPK(key), skPendingLink)
	want := before.Add(ttl).Unix()
	if got := getN(raw, attrTTL); got != want {
		t.Fatalf("ttl = %d, want %d (epoch seconds)", got, want)
	}
	// Belt and braces on the unit itself: a millisecond value for a 2026 date is
	// three orders of magnitude too large, and would sit in the year 50 000.
	if got := getN(raw, attrTTL); got > 4_000_000_000 {
		t.Fatalf("ttl = %d looks like milliseconds; DynamoDB would silently never expire this item", got)
	}
	// The store's own deadline is a padded RFC 3339 string, because the consume
	// condition compares it lexicographically.
	if got := getS(raw, attrExpiresAt); got != formatTime(before.Add(ttl)) {
		t.Errorf("%s = %q, want %q", attrExpiresAt, got, formatTime(before.Add(ttl)))
	}
}

// TestPendingLinkExpiredReadsAsAbsent is the §4.5 rule: TTL deletion is
// best-effort and can lag by roughly 48 hours, so every read re-checks the
// expiry and treats a late item as gone. Both the consuming and the
// non-consuming path have to do it.
func TestPendingLinkExpiredReadsAsAbsent(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	store, client := newStore(t, func(o *Options) { o.Now = clock.now })
	pending := store.PendingLinks()
	ctx := context.Background()

	consuming, stash := linkTokenKey(), conflictKey("stale@example.test", "acme")
	for _, key := range []string{consuming, stash} {
		if err := pending.Save(ctx, key, sampleMeta(), time.Minute); err != nil {
			t.Fatalf("Save %s: %v", key, err)
		}
	}
	clock.advance(2 * time.Minute)
	for _, key := range []string{consuming, stash} {
		if _, err := pending.Get(ctx, key); !errors.Is(err, ErrPendingLinkExpired) {
			t.Errorf("Get %s past its deadline = %v, want ErrPendingLinkExpired", key, err)
		}
		// Left for TTL rather than deleted on the read path, so the classification
		// survives a retry. A later Get answers not-found either way.
		if raw := rawItem(t, client, store.table, pendingLinkPK(key), skPendingLink); len(raw) == 0 {
			t.Errorf("%s was deleted by a failed read; the expiry classification is then unavailable to a retry", key)
		}
	}
}

// TestPendingLinkWithoutATTLNeverExpires reproduces MemoryPendingLinks' own
// reading of a non-positive ttl (oauth_wire.go:863-866): no deadline at all.
func TestPendingLinkWithoutATTLNeverExpires(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	store, client := newStore(t, func(o *Options) { o.Now = clock.now })
	pending := store.PendingLinks()
	ctx := context.Background()

	key := conflictKey("forever@example.test", "acme")
	if err := pending.Save(ctx, key, sampleMeta(), 0); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw := rawItem(t, client, store.table, pendingLinkPK(key), skPendingLink)
	if _, present := raw[attrTTL]; present {
		t.Errorf("a zero ttl still wrote %s = %v", attrTTL, raw[attrTTL])
	}
	if _, present := raw[attrExpiresAt]; present {
		t.Errorf("a zero ttl still wrote %s = %v", attrExpiresAt, raw[attrExpiresAt])
	}

	clock.advance(365 * 24 * time.Hour)
	if _, err := pending.Get(ctx, key); err != nil {
		t.Errorf("Get a year later = %v, want nil — a zero ttl means no deadline", err)
	}
	// And the same for a consuming namespace: attribute_exists(PK) alone must
	// carry it, or the condition would reject every deadline-less entry.
	single := oauthStateKey()
	if err := pending.Save(ctx, single, sampleMeta(), 0); err != nil {
		t.Fatalf("Save single-use: %v", err)
	}
	if _, err := pending.Get(ctx, single); err != nil {
		t.Errorf("Get a deadline-less single-use entry = %v, want nil", err)
	}
}

// TestPendingLinkSaveOverwrites: MemoryPendingLinks assigns into its map
// (oauth_wire.go:868), so a re-Save of one key replaces the entry rather than
// failing.
func TestPendingLinkSaveOverwrites(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	pending := store.PendingLinks()
	ctx := context.Background()

	key := conflictKey("replace@example.test", "acme")
	first := sampleMeta()
	second := sampleMeta()
	if err := pending.Save(ctx, key, first, time.Hour); err != nil {
		t.Fatalf("Save first: %v", err)
	}
	if err := pending.Save(ctx, key, second, time.Hour); err != nil {
		t.Fatalf("Save second: %v", err)
	}
	got, err := pending.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UserID != second.UserID {
		t.Errorf("Get = user %q, want the second Save's %q", got.UserID, second.UserID)
	}
}

func TestPendingLinkRejectsAnEmptyState(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	pending := store.PendingLinks()
	ctx := context.Background()

	if err := pending.Save(ctx, "", sampleMeta(), time.Hour); !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("Save(\"\") = %v, want ErrInvalidIdentifier", err)
	}
	// Get answers the caller-facing not-found instead, because an empty state must
	// not resolve to whatever such a key happens to hold and the outcome is the
	// same either way.
	if _, err := pending.Get(ctx, ""); !errors.Is(err, ErrPendingLinkNotFound) {
		t.Errorf("Get(\"\") = %v, want ErrPendingLinkNotFound", err)
	}
	if err := pending.Save(ctx, strings.Repeat("x", maxStateKeyLen+1), sampleMeta(), time.Hour); !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("Save(oversized) = %v, want ErrInvalidIdentifier", err)
	}
}

// TestPendingLinkNonAtomicModeIsTheParityEscapeHatch: with
// Options.NonAtomicSingleUseTokens the single-use namespaces read without
// consuming, which is the reference's behaviour verbatim.
func TestPendingLinkNonAtomicModeIsTheParityEscapeHatch(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t, func(o *Options) { o.NonAtomicSingleUseTokens = true })
	pending := store.PendingLinks()
	ctx := context.Background()

	key := linkTokenKey()
	if err := pending.Save(ctx, key, sampleMeta(), time.Hour); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for i := range 2 {
		if _, err := pending.Get(ctx, key); err != nil {
			t.Fatalf("Get %d in non-atomic mode = %v, want nil both times", i, err)
		}
	}
	// An unknown key must still be unknown, so this is a relaxation of the
	// consume and not of the lookup.
	if _, err := pending.Get(ctx, linkTokenKey()); !errors.Is(err, ErrPendingLinkNotFound) {
		t.Errorf("Get of an unknown key in non-atomic mode = %v, want ErrPendingLinkNotFound", err)
	}
}
