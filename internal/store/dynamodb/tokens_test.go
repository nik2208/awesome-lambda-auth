package dynamodb

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// newUser is the fixture the token and session tests share: a stored user with no
// token state.
func newUser(t *testing.T, store *Store, tenantID string) auth.User {
	t.Helper()
	u := sampleUser(tenantID)
	u.ResetTokenHash = ""
	u.ResetTokenExpiresAt = nil
	created, err := store.CreateUser(context.Background(), u)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return created
}

func TestResetTokenIssueConsumeClear(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	hash := hashOf("reset-1")
	expiry := time.Now().Add(time.Hour)
	if err := store.UpdateResetToken(ctx, u.ID, "acme", hash, expiry); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(rawItem(t, client, store.table, familyReset.pk(hash), skToken)) == 0 {
		t.Fatal("pointer item missing; a tenant-less lookup has nothing to resolve")
	}

	got, err := store.GetUserByResetTokenHash(ctx, hash)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("resolved to %q, want %q", got.ID, u.ID)
	}
	// The pre-image must carry the hash and expiry, because Service.ResetPassword
	// checks them on the returned user (service.go:255).
	if got.ResetTokenHash != hash {
		t.Fatalf("returned resetTokenHash = %q, want %q", got.ResetTokenHash, hash)
	}
	if got.ResetTokenExpiresAt == nil || !got.ResetTokenExpiresAt.Equal(expiry.UTC()) {
		t.Fatalf("returned expiry = %v, want %v", got.ResetTokenExpiresAt, expiry.UTC())
	}

	// The read consumed it, so a second attempt must fail.
	if _, err := store.GetUserByResetTokenHash(ctx, hash); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("second consume: err = %v, want ErrInvalidToken", err)
	}

	// Clear is an idempotent no-op afterwards. If it were conditional on the hash
	// still being there, ResetPassword would fail after already changing the
	// password.
	if err := store.ClearResetToken(ctx, u.ID, "acme"); err != nil {
		t.Fatalf("clear after consume: %v", err)
	}
	if err := store.ClearResetToken(ctx, u.ID, "acme"); err != nil {
		t.Fatalf("clear twice: %v", err)
	}
	if err := store.ClearResetToken(ctx, uniqueID("usr"), "acme"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("clear for missing user: err = %v, want ErrUserNotFound", err)
	}
}

func TestResetTokenExpiryIsEnforcedByTheCondition(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	hash := hashOf("stale")
	if err := store.UpdateResetToken(ctx, u.ID, "acme", hash, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := store.GetUserByResetTokenHash(ctx, hash); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("expired token: err = %v, want ErrInvalidToken", err)
	}
}

func TestReissuedResetTokenInvalidatesThePrevious(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	old := hashOf("first")
	fresh := hashOf("second")
	expiry := time.Now().Add(time.Hour)
	if err := store.UpdateResetToken(ctx, u.ID, "acme", old, expiry); err != nil {
		t.Fatalf("issue first: %v", err)
	}
	if err := store.UpdateResetToken(ctx, u.ID, "acme", fresh, expiry); err != nil {
		t.Fatalf("issue second: %v", err)
	}

	// The stale pointer still resolves to the user — it is a hint, reaped by TTL —
	// but the profile's hash has moved on, so the consume condition cannot match.
	if _, err := store.GetUserByResetTokenHash(ctx, old); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("superseded token: err = %v, want ErrInvalidToken", err)
	}
	if _, err := store.GetUserByResetTokenHash(ctx, fresh); err != nil {
		t.Fatalf("current token: %v", err)
	}
}

func TestUnknownResetTokenIsInvalid(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	for _, hash := range []string{"", hashOf("never-issued")} {
		if _, err := store.GetUserByResetTokenHash(ctx, hash); !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("hash %q: err = %v, want ErrInvalidToken", hash, err)
		}
	}
}

func TestIssueResetTokenForMissingUser(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	err := store.UpdateResetToken(ctx, uniqueID("usr"), "acme", hashOf("x"), time.Now().Add(time.Hour))
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestIssueResetTokenIsRetrySafe(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	hash := hashOf("retried")
	expiry := time.Now().Add(time.Hour)
	// A retried call writes the same pointer. attribute_not_exists alone would
	// reject it, turning a transient network blip into a permanent failure.
	for i := range 3 {
		if err := store.UpdateResetToken(ctx, u.ID, "acme", hash, expiry); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := store.GetUserByResetTokenHash(ctx, hash); err != nil {
		t.Fatalf("consume after retries: %v", err)
	}
}

func TestUpdatePassword(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	if err := store.UpdatePassword(ctx, u.ID, "acme", "$2a$10$newhash"); err != nil {
		t.Fatalf("update password: %v", err)
	}
	got, err := store.GetUserByID(ctx, u.ID, "acme")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.PasswordHash != "$2a$10$newhash" {
		t.Fatalf("passwordHash = %q", got.PasswordHash)
	}
	if err := store.UpdatePassword(ctx, u.ID, "other", "x"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("cross-tenant update: err = %v, want ErrUserNotFound", err)
	}
	if err := store.UpdatePassword(ctx, uniqueID("usr"), "acme", "x"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user: err = %v, want ErrUserNotFound", err)
	}
}

// TestConcurrentResetConsumeHasOneWinner is the single-use guarantee stated as a
// race: many callers, one link, exactly one success.
func TestConcurrentResetConsumeHasOneWinner(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	const rounds, racers = 12, 8
	for round := range rounds {
		hash := hashOf(uniqueID("reset"))
		if err := store.UpdateResetToken(ctx, u.ID, "acme", hash, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("round %d issue: %v", round, err)
		}

		var (
			wg      sync.WaitGroup
			gate    = make(chan struct{})
			mu      sync.Mutex
			winners int
			others  []error
		)
		for range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				_, err := store.GetUserByResetTokenHash(ctx, hash)
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					winners++
					return
				}
				if !errors.Is(err, auth.ErrInvalidToken) {
					others = append(others, err)
				}
			}()
		}
		close(gate)
		wg.Wait()

		if winners != 1 {
			t.Fatalf("round %d: %d callers consumed the same token, want exactly 1", round, winners)
		}
		if len(others) > 0 {
			t.Fatalf("round %d: unexpected errors from losers: %v", round, others)
		}
	}
}

// TestNonAtomicModeIsTheParityEscapeHatch pins the documented behaviour of the
// opt-out: it really does reproduce the reference's hole, so nobody enables it
// believing otherwise.
func TestNonAtomicModeIsTheParityEscapeHatch(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t, func(o *Options) { o.NonAtomicSingleUseTokens = true })
	ctx := context.Background()
	u := newUser(t, store, "acme")

	hash := hashOf("parity")
	if err := store.UpdateResetToken(ctx, u.ID, "acme", hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	for i := range 2 {
		if _, err := store.GetUserByResetTokenHash(ctx, hash); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	if err := store.ClearResetToken(ctx, u.ID, "acme"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, err := store.GetUserByResetTokenHash(ctx, hash); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("after clear: err = %v, want ErrInvalidToken", err)
	}
}
