package dynamodb

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// The two races that matter, run against DynamoDB Local rather than a fake,
// because "exactly one winner" is a property of DynamoDB's conditional writes and
// transactions and cannot be asserted about a mock of them.
//
// Each is repeated: a single round can pass by luck when the goroutines happen to
// serialise. The rounds are cheap because the table is created once per test.
const (
	raceRounds = 30
	raceRacers = 8
)

// TestConcurrentRegistrationHasOneWinner is the registration guarantee: two
// concurrent registrations of the same address, one wins.
//
// The interesting part is that this cannot be done with a uniqueness index — a
// GSI cannot enforce uniqueness and is eventually consistent — so it is a
// separate item guarded by attribute_not_exists inside a TransactWriteItems.
func TestConcurrentRegistrationHasOneWinner(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	for round := range raceRounds {
		email := uniqueEmail("race")
		results := runRace(raceRacers, func() error {
			u := sampleUser("acme")
			u.Email = email
			_, err := store.CreateUser(ctx, u)
			return err
		})

		winners, losers, unexpected := tally(results, auth.ErrUserExists)
		if winners != 1 {
			t.Fatalf("round %d: %d registrations of %s succeeded, want exactly 1", round, winners, email)
		}
		if losers != raceRacers-1 {
			t.Fatalf("round %d: %d losers reported ErrUserExists, want %d (unexpected: %v)",
				round, losers, raceRacers-1, unexpected)
		}

		// The winner must be the user the store can actually resolve — a race that
		// leaves the uniqueness item pointing at a losing id would be worse than a
		// double registration.
		got, err := store.GetUserByEmail(ctx, email, "acme")
		if err != nil {
			t.Fatalf("round %d: resolve winner: %v", round, err)
		}
		if _, err := store.GetUserByID(ctx, got.ID, "acme"); err != nil {
			t.Fatalf("round %d: uniqueness item points at a user that does not exist: %v", round, err)
		}
	}
}

// TestConcurrentRegistrationOfTheSameIDHasOneWinner covers the other half of the
// transaction: the profile item's own attribute_not_exists.
func TestConcurrentRegistrationOfTheSameIDHasOneWinner(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	for round := range raceRounds {
		userID := uniqueID("usr")
		results := runRace(raceRacers, func() error {
			u := sampleUser("acme")
			u.ID = userID
			_, err := store.CreateUser(ctx, u)
			return err
		})
		winners, losers, unexpected := tally(results, auth.ErrUserExists)
		if winners != 1 {
			t.Fatalf("round %d: %d registrations of id %s succeeded, want exactly 1", round, winners, userID)
		}
		if losers != raceRacers-1 {
			t.Fatalf("round %d: %d losers reported ErrUserExists, want %d (unexpected: %v)",
				round, losers, raceRacers-1, unexpected)
		}
	}
}

// TestConcurrentRefreshHasOneWinner is the rotation guarantee: several requests
// present the same refresh token at once, exactly one rotation commits, and the
// losers — whose token is now a spent generation — revoke the whole family.
//
// The two barriers matter. Letting every racer complete its read before any write
// is what forces the race onto the rotation condition itself; without them a
// racer can arrive late, take the read-path replay branch instead, and the test
// would pass without ever exercising the conditional write.
func TestConcurrentRefreshHasOneWinner(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	for round := range raceRounds {
		sess := sampleSession(u)
		sess.CreatedAt = time.Now().UTC()
		sess.ExpiresAt = sess.CreatedAt.Add(24 * time.Hour)
		if _, err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("round %d: create session: %v", round, err)
		}

		var (
			reads   sync.WaitGroup
			writes  sync.WaitGroup
			gate    = make(chan struct{})
			mu      sync.Mutex
			winners int
			losers  int
			other   []error
		)
		for range raceRacers {
			reads.Add(1)
			writes.Add(1)
			go func() {
				defer writes.Done()
				// Each goroutine is a separate Lambda invocation, so each gets its
				// own rotation scope — exactly as the HTTP layer installs one per
				// request.
				reqCtx := WithRotationScope(context.Background())
				_, readErr := store.GetSessionByRefreshTokenHash(reqCtx, sess.RefreshTokenHash)
				reads.Done()
				<-gate
				if readErr != nil {
					mu.Lock()
					other = append(other, readErr)
					mu.Unlock()
					return
				}
				next := sess
				next.RefreshTokenHash = hashOf(uniqueID("refresh"))
				err := store.UpdateSession(reqCtx, next)

				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					winners++
				case errors.Is(err, auth.ErrSessionNotFound), errors.Is(err, auth.ErrSessionRevoked):
					losers++
				default:
					other = append(other, err)
				}
			}()
		}
		reads.Wait()
		close(gate)
		writes.Wait()

		if len(other) > 0 {
			t.Fatalf("round %d: unexpected errors: %v", round, other)
		}
		if winners != 1 {
			t.Fatalf("round %d: %d concurrent refreshes committed, want exactly 1", round, winners)
		}
		if losers != raceRacers-1 {
			t.Fatalf("round %d: %d losers, want %d", round, losers, raceRacers-1)
		}

		// The losers held a token that had just been rotated out, which is
		// indistinguishable from a leaked one, so the family must be dead.
		raw := rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
		if getS(raw, attrRevokedAt) == "" {
			t.Fatalf("round %d: family survived a concurrent refresh", round)
		}
		if got := getS(raw, attrRevokedReason); got != reasonReplay {
			t.Fatalf("round %d: revokedReason = %q, want %q", round, got, reasonReplay)
		}
	}
}

// TestConcurrentRefreshWithoutAScopeIsDetectedLate pins the residual documented
// in data-model.md §4.3: with no precondition available the store cannot make the
// rotation conditional, so more than one caller can commit. The replay is caught
// on the next use instead. This is asserted rather than left implicit so that
// enabling the degraded path is a decision, not a surprise.
func TestConcurrentRefreshWithoutAScopeIsDetectedLate(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Two rotations off the same starting hash, neither carrying a precondition.
	first := sess
	first.RefreshTokenHash = hashOf(uniqueID("refresh"))
	if err := store.UpdateSession(context.Background(), first); err != nil {
		t.Fatalf("first degraded rotation: %v", err)
	}
	second := sess
	second.RefreshTokenHash = hashOf(uniqueID("refresh"))
	if err := store.UpdateSession(context.Background(), second); err != nil {
		t.Fatalf("second degraded rotation should also succeed without a precondition: %v", err)
	}

	// The first winner's token is now a spent generation; using it revokes the
	// family — one request later than the scoped path would have.
	if _, err := store.GetSessionByRefreshTokenHash(ctx, first.RefreshTokenHash); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("stale generation: err = %v, want ErrSessionNotFound", err)
	}
	raw := rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
	if got := getS(raw, attrRevokedReason); got != reasonReplay {
		t.Fatalf("revokedReason = %q, want %q", got, reasonReplay)
	}
}

// runRace starts n goroutines behind one gate and collects their errors.
func runRace(n int, fn func() error) []error {
	var (
		wg   sync.WaitGroup
		gate = make(chan struct{})
		mu   sync.Mutex
		out  []error
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			err := fn()
			mu.Lock()
			out = append(out, err)
			mu.Unlock()
		}()
	}
	close(gate)
	wg.Wait()
	return out
}

func tally(results []error, expected error) (winners, losers int, unexpected []error) {
	for _, err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, expected):
			losers++
		default:
			unexpected = append(unexpected, err)
		}
	}
	return winners, losers, unexpected
}
