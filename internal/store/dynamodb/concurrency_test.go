package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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

// TestConcurrentSingleUseConsumeHasOneWinner is the guarantee the four optional
// token stores exist for, asserted on all five families at once: many callers,
// one token, exactly one success.
//
// This is why the lookup is a conditional write and not a read. The core's flow
// is lookup → mutate → clear, three separate store calls with nothing atomic
// across them, so a read-then-write store lets every concurrent caller past the
// lookup and the magic link works twice.
func TestConcurrentSingleUseConsumeHasOneWinner(t *testing.T) {
	t.Parallel()
	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			store, _ := newStore(t)
			ctx := context.Background()
			u := newUser(t, store, "acme")

			for round := range raceRounds {
				hash := hashOf(uniqueID(c.name))
				if err := c.issue(ctx, store, u.ID, "acme", hash, time.Now().Add(time.Hour)); err != nil {
					t.Fatalf("round %d issue: %v", round, err)
				}
				results := runRace(raceRacers, func() error {
					_, err := c.consume(ctx, store, u.ID, "acme", hash)
					return err
				})
				winners, losers, unexpected := tally(results, c.family.invalidErr)
				if winners != 1 {
					t.Fatalf("round %d: %d callers consumed the same %s value, want exactly 1", round, winners, c.name)
				}
				if losers != raceRacers-1 {
					t.Fatalf("round %d: %d losers reported %v, want %d (unexpected: %v)",
						round, losers, c.family.invalidErr, raceRacers-1, unexpected)
				}
			}
		})
	}
}

// TestConcurrentReplacementWhileConsuming is the other race these stores have to
// survive: one caller presents a token while another is issuing its replacement.
//
// Two things must hold however the two interleave. The old value is consumable at
// most once — never once before the replacement and again after, which is what a
// read-then-write, or a consume that compared against the pointer instead of the
// profile, would allow. And the replacement is always valid afterwards, because a
// reissue is an unconditional SET on the profile and cannot be left half-applied
// by a consume racing it.
//
// The random race alone does not cover both orders evenly, and the logged count
// says so: a pointer-backed consume spends a GetItem resolving the pointer first,
// so the reissuer usually wins, while SMS goes straight at the profile and the
// consumers usually do. Hence the two deterministic orders below the fixture —
// the race's job here is to prove there is no third outcome, not to schedule the
// two that are already pinned.
func TestConcurrentReplacementWhileConsuming(t *testing.T) {
	t.Parallel()
	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			store, _ := newStore(t)
			ctx := context.Background()
			u := newUser(t, store, "acme")

			// The two orders, deterministically, before racing them. Both are legal
			// and both have to leave exactly one live value; the race then checks
			// that no third outcome exists.
			first, second := hashOf(uniqueID("a")), hashOf(uniqueID("b"))
			expiry := time.Now().Add(time.Hour)
			if err := c.issue(ctx, store, u.ID, "acme", first, expiry); err != nil {
				t.Fatalf("issue: %v", err)
			}
			if _, err := c.consume(ctx, store, u.ID, "acme", first); err != nil {
				t.Fatalf("consume before the replacement: %v", err)
			}
			if err := c.issue(ctx, store, u.ID, "acme", second, expiry); err != nil {
				t.Fatalf("reissue after a consume: %v", err)
			}
			if _, err := c.consume(ctx, store, u.ID, "acme", second); err != nil {
				t.Fatalf("the replacement issued after a consume is unusable: %v", err)
			}

			// consumedRounds counts how often the consumers beat the reissuer, and is
			// reported rather than asserted: it is the evidence that the race is
			// really interleaving both ways rather than passing because one side
			// always wins.
			consumedRounds := 0
			for round := range raceRounds {
				old, replacement := hashOf(uniqueID("old")), hashOf(uniqueID("new"))
				if err := c.issue(ctx, store, u.ID, "acme", old, expiry); err != nil {
					t.Fatalf("round %d issue: %v", round, err)
				}

				var (
					wg        sync.WaitGroup
					gate      = make(chan struct{})
					mu        sync.Mutex
					consumed  int
					reissued  error
					unexpecte []error
				)
				// One reissuer against raceRacers-1 consumers of the value it is
				// replacing.
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-gate
					err := c.issue(ctx, store, u.ID, "acme", replacement, expiry)
					mu.Lock()
					reissued = err
					mu.Unlock()
				}()
				for range raceRacers - 1 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-gate
						_, err := c.consume(ctx, store, u.ID, "acme", old)
						mu.Lock()
						defer mu.Unlock()
						switch {
						case err == nil:
							consumed++
						case errors.Is(err, c.family.invalidErr):
						default:
							unexpecte = append(unexpecte, err)
						}
					}()
				}
				close(gate)
				wg.Wait()

				if len(unexpecte) > 0 {
					t.Fatalf("round %d: unexpected errors: %v", round, unexpecte)
				}
				if reissued != nil {
					t.Fatalf("round %d: reissue lost to a concurrent consume: %v", round, reissued)
				}
				if consumed > 1 {
					t.Fatalf("round %d: the replaced value was consumed %d times, want at most 1", round, consumed)
				}
				if consumed == 1 {
					consumedRounds++
				}
				// Whoever won, the replacement is the only live value now: usable
				// exactly once.
				if _, err := c.consume(ctx, store, u.ID, "acme", replacement); err != nil {
					t.Fatalf("round %d: the replacement is not usable: %v", round, err)
				}
				if _, err := c.consume(ctx, store, u.ID, "acme", replacement); !errors.Is(err, c.family.invalidErr) {
					t.Fatalf("round %d: the replacement survived its own consume: err = %v", round, err)
				}
				// And the replaced value is dead either way.
				if _, err := c.consume(ctx, store, u.ID, "acme", old); !errors.Is(err, c.family.invalidErr) {
					t.Fatalf("round %d: the replaced value is still live: err = %v", round, err)
				}
			}
			t.Logf("the replaced value was consumed in %d of %d rounds", consumedRounds, raceRounds)
		})
	}
}

// TestConcurrentEmailChangeConfirmHasOneWinner. Promoting the pending address is
// three writes across two partitions, so "exactly one" has to come from the
// transaction rather than from the order the callers arrive in. A second winner
// would mean two uniqueness items for one mailbox, or one deleted twice.
func TestConcurrentEmailChangeConfirmHasOneWinner(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	for round := range raceRounds {
		u := newUser(t, store, "acme")
		oldEmail := u.Email
		newEmail := uniqueEmail("confirmed")
		if err := store.UpdateEmailChangeToken(ctx, u.ID, "acme", newEmail, hashOf(uniqueID("echg")), time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("round %d issue: %v", round, err)
		}

		results := runRace(raceRacers, func() error {
			return store.ApplyEmailChange(ctx, u.ID, "acme")
		})

		var winners int
		var unexpected []error
		for _, err := range results {
			switch {
			case err == nil:
				winners++
			// A loser sees the address already taken, or the pending address gone
			// from under it. Both are correct refusals; neither may be a fault.
			case errors.Is(err, auth.ErrUserExists),
				errors.Is(err, auth.ErrInvalidToken),
				errors.Is(err, ErrNoPendingEmailChange):
			default:
				unexpected = append(unexpected, err)
			}
		}
		if len(unexpected) > 0 {
			t.Fatalf("round %d: unexpected errors: %v", round, unexpected)
		}
		if winners != 1 {
			t.Fatalf("round %d: %d concurrent confirmations applied, want exactly 1", round, winners)
		}

		got, err := store.GetUserByEmail(ctx, newEmail, "acme")
		if err != nil || got.ID != u.ID {
			t.Fatalf("round %d: the new address resolves to %q (err %v)", round, got.ID, err)
		}
		mustNotExist(t, client, store.table, emailPK("acme", oldEmail), skEmail)
	}
}

// TestConcurrentPendingLinkConsumeHasOneWinner is the whole reason
// PendingLinkStore exists server-side.
//
// The core's linking flow is Get → write the link → Delete, three separate store
// calls with nothing atomic across them, and it discards Delete's error
// (oauth_wire.go:765-805). So a store whose Get merely reads would let two
// Lambdas holding one account-link token both pass and both write a binding. Here
// the Get *is* the conditional write, and exactly one caller can satisfy it.
//
// Both single-use namespaces are covered, because the OAuth state nonce depends on
// the same guarantee for a different reason: it is what makes a state
// unreplayable (oauth_wire.go:481-484).
func TestConcurrentPendingLinkConsumeHasOneWinner(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	pending := store.PendingLinks()
	ctx := context.Background()

	for _, namespace := range []struct {
		name string
		key  func() string
	}{
		{"oauth-state", oauthStateKey},
		{"link-token", linkTokenKey},
	} {
		t.Run(namespace.name, func(t *testing.T) {
			for round := range raceRounds {
				key := namespace.key()
				meta := sampleMeta()
				if err := pending.Save(ctx, key, meta, time.Hour); err != nil {
					t.Fatalf("round %d save: %v", round, err)
				}

				var consumed atomic.Int64
				results := runRace(raceRacers, func() error {
					got, err := pending.Get(ctx, key)
					if err != nil {
						return err
					}
					// A winner must get the entry itself, not an empty struct: the
					// pre-image is what the linking flow builds the binding from.
					if got.UserID != meta.UserID || got.ProviderAccountID != meta.ProviderAccountID {
						return fmt.Errorf("winner got %+v, want the saved meta", got)
					}
					consumed.Add(1)
					return nil
				})

				winners, losers, unexpected := tally(results, ErrPendingLinkNotFound)
				if len(unexpected) > 0 {
					t.Fatalf("round %d: unexpected errors: %v", round, unexpected)
				}
				if winners != 1 || int(consumed.Load()) != 1 {
					t.Fatalf("round %d: %d of %d concurrent consumptions succeeded, want exactly 1", round, winners, raceRacers)
				}
				if losers != raceRacers-1 {
					t.Fatalf("round %d: %d losers reported not-found, want %d", round, losers, raceRacers-1)
				}
				mustNotExist(t, client, store.table, pendingLinkPK(key), skPendingLink)
			}
		})
	}
}

// TestConcurrentLinkRebindLeavesNoStaleEntry is the concurrent form of upstream
// nik2208/awesome-go-auth#37.
//
// Every racer rebinds one provider account to a different user with a different
// link id, so several of them legitimately succeed — a rebind is not a constraint
// to be lost, it is an ordinary write, and each one supersedes the last. What must
// hold afterwards is that the outcome is *one* consistent binding rather than a
// mixture: one canonical item, one surviving LINKID pointer belonging to it, and
// no losing owner still advertising the account on their own list.
//
// A store built the reference's way fails this on the first round.
func TestConcurrentLinkRebindLeavesNoStaleEntry(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	links := store.LinkedAccounts()
	ctx := context.Background()

	for round := range raceRounds {
		providerID := "sub-" + randomHex(8)
		candidates := make([]auth.OAuthLinkedAccount, raceRacers)
		for i := range candidates {
			candidates[i] = sampleLink(uniqueID("usr"), "google", providerID)
		}

		var next atomic.Int64
		results := runRace(raceRacers, func() error {
			return links.Save(ctx, candidates[next.Add(1)-1])
		})

		var unexpected []error
		for _, err := range results {
			switch {
			case err == nil:
			// Losing the compare-and-set often enough to exhaust the retries is a
			// legitimate outcome under eight simultaneous rebinds, and is reported
			// rather than silently dropping a link.
			case errors.Is(err, ErrLinkedAccountConflict):
			default:
				unexpected = append(unexpected, err)
			}
		}
		if len(unexpected) > 0 {
			t.Fatalf("round %d: unexpected errors: %v", round, unexpected)
		}

		live := assertSingleBinding(t, store, client, "google", providerID, candidates)
		// And the survivor must be one racer's write rather than a mixture of two:
		// the link id and the user id have to come from the same candidate.
		matched := false
		for _, c := range candidates {
			if c.ID != live.ID {
				continue
			}
			matched = true
			if live.UserID != c.UserID {
				t.Fatalf("round %d: binding names link %q but user %q, which belongs to nobody",
					round, live.ID, live.UserID)
			}
		}
		if !matched {
			t.Fatalf("round %d: surviving link %q was written by none of the racers", round, live.ID)
		}
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
