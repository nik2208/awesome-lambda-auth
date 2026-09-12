package migrating

import (
	"context"
	"errors"
	"sync"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"

	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// markedUser is an imported row as cmd/migrate writes one: a real address, an
// empty password hash, and the marker.
func markedUser(t *testing.T, email string, ref SourceRef) auth.User {
	t.Helper()
	id, err := NewUserID()
	if err != nil {
		t.Fatalf("NewUserID: %v", err)
	}
	return auth.User{ID: id, Email: email, IsEmailVerified: true}
}

// markedCtx is a request context carrying the marker the store's profile read
// would have filed for this user. It is how every verifier test here supplies a
// marker, because there is no longer any way to put one on an auth.User — which
// is the property that retired the disclosure deviation.
func markedCtx(t *testing.T, user auth.User, ref SourceRef) context.Context {
	t.Helper()
	ctx := ddbstore.WithMigrationScope(context.Background())
	ddbstore.RecordMigrationMarkerForTest(ctx, user.ID, ref.Marker())
	return ctx
}

// readCtx is a request context in which the profile WAS read and carried no
// marker: an ordinary account. Distinct from a bare context, which means
// "nothing was read" and is a wiring fault.
func readCtx(t *testing.T, user auth.User) context.Context {
	t.Helper()
	ctx := ddbstore.WithMigrationScope(context.Background())
	ddbstore.RecordMigrationMarkerForTest(ctx, user.ID, ddbstore.MigrationMarker{})
	return ctx
}

// THE test of the gate. The upstream seam states as a requirement, not a style
// note, that a verifier keys on its marker and answers (false, false, nil)
// before doing anything else when it is absent — because the hook is reached by
// every login whose stored hash failed to verify, including OAuth-only and
// magic-link-only accounts that never had a password, from an unauthenticated
// route.
//
// So this asserts the strongest available form of it: the directory is not
// called. Not "the answer is no" — no call at all.
//
// The last two cases are the ones the carrier adds, and both must behave like an
// unmarked account. A verifier reached with NO record at all — no scope
// installed, or a path that never read a profile — has to fail closed rather
// than look anywhere else: a fallback to auth.User.Metadata would put the marker
// back on the wire, and assuming "migrating" would be the amplifier itself.
func TestVerifierNeverReachesTheSourceWithoutAMarker(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	dir.add("nobody@example.test", nil, "anything")
	m := newMigrating(t, dir)
	verify := m.PasswordVerifier()

	ordinary := auth.User{ID: "usr_a", Email: "a@example.test"}
	otherPool := auth.User{ID: "usr_e", Email: "e@example.test"}
	otherSource := auth.User{ID: "usr_f", Email: "f@example.test"}
	unscoped := auth.User{ID: "usr_g", Email: "g@example.test"}
	stray := auth.User{ID: "usr_h", Email: "h@example.test"}

	strayCtx := ddbstore.WithMigrationScope(context.Background())
	ddbstore.RecordMigrationMarkerForTest(strayCtx, "usr_somebody_else", testRef().Marker())

	cases := []struct {
		name string
		ctx  context.Context
		user auth.User
	}{
		{"an ordinary account, read and unmarked", readCtx(t, ordinary), ordinary},
		{"a marker naming another pool", markedCtx(t, otherPool, SourceRef{Source: testSource, Pool: testOtherPool}), otherPool},
		{"a marker naming another source family", markedCtx(t, otherSource, SourceRef{Source: "auth0", Pool: testPool}), otherSource},
		{"no scope on the request at all", context.Background(), unscoped},
		{"a marker recorded for a different user", strayCtx, stray},
	}

	for _, tc := range cases {
		ok, migrated, err := verify(tc.ctx, tc.user, "whatever the request carried")
		if ok || migrated || err != nil {
			t.Errorf("%s: verifier answered (%v, %v, %v), want (false, false, nil)", tc.name, ok, migrated, err)
		}
	}

	if _, verifyCalls := dir.counts(); verifyCalls != 0 {
		t.Fatalf("the source was asked %d times about accounts with no marker for this pool; "+
			"that is the amplifier the marker gate exists to prevent", verifyCalls)
	}
}

func TestVerifierAdoptsOnASuccessfulCheck(t *testing.T) {
	t.Parallel()
	const email = "ada@example.test"
	dir := newFakeDirectory()
	dir.add(email, map[string]string{"email": email}, "the old password")
	m := newMigrating(t, dir)

	u := markedUser(t, email, testRef())
	ok, migrated, err := m.PasswordVerifier()(markedCtx(t, u, testRef()), u, "the old password")
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	if !ok || !migrated {
		t.Fatalf("verifier answered (%v, %v), want (true, true): migrated=false would leave the deployment "+
			"asking the old directory on every login forever", ok, migrated)
	}
}

// The address the pool is asked about is the STORED one, so no value taken
// straight from a request body is forwarded to somebody else's directory.
func TestVerifierAsksAboutTheStoredAddress(t *testing.T) {
	t.Parallel()
	const stored = "ada@example.test"
	dir := newFakeDirectory()
	dir.add(stored, map[string]string{"email": stored}, "pw")
	m := newMigrating(t, dir)

	u := markedUser(t, stored, testRef())
	if _, _, err := m.PasswordVerifier()(markedCtx(t, u, testRef()), u, "pw"); err != nil {
		t.Fatalf("verifier: %v", err)
	}
	dir.mu.Lock()
	defer dir.mu.Unlock()
	if dir.lastVerify != stored {
		t.Errorf("the source was asked about %q, want the stored address %q", dir.lastVerify, stored)
	}
}

// Every refusal the source can make is a DECISION, answered (false, false, nil).
// Rendering any of them as an error would answer 500 where the route must answer
// 401, and would make them distinguishable from one another by a client.
func TestVerifierAnswersNoRatherThanErrorForEveryRefusal(t *testing.T) {
	t.Parallel()
	refusals := []error{
		awsintegration.ErrCognitoPasswordRejected,
		awsintegration.ErrCognitoUserNotFound,
		awsintegration.ErrCognitoUserNotConfirmed,
		awsintegration.ErrCognitoPasswordResetRequired,
		awsintegration.ErrCognitoChallenge,
	}
	for _, refusal := range refusals {
		t.Run(refusal.Error(), func(t *testing.T) {
			t.Parallel()
			dir := newFakeDirectory()
			dir.verifyErr = refusal
			m := newMigrating(t, dir)

			u := markedUser(t, "ada@example.test", testRef())
			ok, migrated, err := m.PasswordVerifier()(markedCtx(t, u, testRef()), u, "pw")
			if ok || migrated || err != nil {
				t.Fatalf("verifier answered (%v, %v, %v), want (false, false, nil)", ok, migrated, err)
			}
		})
	}
}

// "The pool did not answer" is the one outcome that may become an error, and the
// login then fails closed on it, which the core turns into a generic 500.
func TestVerifierFailsClosedWhenTheSourceCannotDecide(t *testing.T) {
	t.Parallel()
	failures := []error{
		awsintegration.ErrCognitoThrottled,
		awsintegration.ErrCognitoClientHasSecret,
		errors.New("the pool did not answer"),
	}
	for _, failure := range failures {
		t.Run(failure.Error(), func(t *testing.T) {
			t.Parallel()
			dir := newFakeDirectory()
			dir.verifyErr = failure
			m := newMigrating(t, dir)

			u := markedUser(t, "ada@example.test", testRef())
			ok, migrated, err := m.PasswordVerifier()(markedCtx(t, u, testRef()), u, "pw")
			if err == nil {
				t.Fatal("verifier answered nil error for a source that could not decide; the login would have proceeded")
			}
			if ok || migrated {
				t.Errorf("verifier answered (%v, %v) alongside an error; the core ignores ok, but saying yes here is wrong on its face", ok, migrated)
			}
			if !errors.Is(err, failure) {
				t.Errorf("the cause is no longer reachable: %v", err)
			}
		})
	}
}

// An empty password is never adopted by the core, so the round trip is not made.
func TestVerifierSpendsNoCallOnAnEmptyPassword(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	m := newMigrating(t, dir)

	u := markedUser(t, "ada@example.test", testRef())
	ok, migrated, err := m.PasswordVerifier()(markedCtx(t, u, testRef()), u, "")
	if ok || migrated || err != nil {
		t.Fatalf("verifier answered (%v, %v, %v), want (false, false, nil)", ok, migrated, err)
	}
	if _, verifyCalls := dir.counts(); verifyCalls != 0 {
		t.Errorf("the source was asked %d times about an empty password the core would never adopt", verifyCalls)
	}
}

// Over budget the answer is the same one a wrong password gets, so engaging the
// limiter is not observable from outside.
func TestVerifierRateLimitIsInvisibleAndBounds(t *testing.T) {
	t.Parallel()
	const email = "ada@example.test"
	dir := newFakeDirectory()
	dir.add(email, map[string]string{"email": email}, "the old password")
	m := newMigrating(t, dir, func(o *Options) {
		o.SubjectBurst = 2
		o.SubjectPerMinute = 0.0001 // effectively no refill during the test
	})
	user := markedUser(t, email, testRef())
	verify := m.PasswordVerifier()

	// A fresh carrier per call, because the limiter's budget is per process while
	// the carrier is per request: reusing one would also be reusing a record the
	// first call consumed, and the test would pass for the wrong reason.
	//
	// Two calls are within budget and reach the source; the third is not.
	for i := range 2 {
		if _, _, err := verify(markedCtx(t, user, testRef()), user, "wrong"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	ok, migrated, err := verify(markedCtx(t, user, testRef()), user, "the old password")
	if ok || migrated || err != nil {
		t.Fatalf("the refused call answered (%v, %v, %v), want the same (false, false, nil) a wrong password gets", ok, migrated, err)
	}
	if _, verifyCalls := dir.counts(); verifyCalls != 2 {
		t.Fatalf("the source was called %d times against a burst of 2; the bound is not holding", verifyCalls)
	}
}

// The marker-flip race, against DynamoDB Local and through the real core.
//
// Two concurrent logins of one migrating user both find a hash that does not
// verify, both ask the directory, both are told yes, and both drive the core's
// adoption. The decision this pins is that adoption is IDEMPOTENT rather than
// exclusive: both succeed, the stored hash verifies the password afterwards, and
// the marker is gone. The interleaving that must never happen is the one where
// the marker is dropped while the hash is still the imported empty one — that
// account would have no way back in, because an empty hash verifies nothing and
// a missing marker makes the verifier answer no.
func TestConcurrentLoginsAdoptIdempotently(t *testing.T) {
	t.Parallel()
	const (
		email    = "ada@example.test"
		password = "the old password"
	)
	dir := newFakeDirectory()
	dir.add(email, map[string]string{"email": email}, password)
	m := newMigrating(t, dir)

	seeded, err := m.CreateMigratedUser(t.Context(), markedUser(t, email, testRef()), testRef().Marker())
	if err != nil {
		t.Fatalf("seed the imported row: %v", err)
	}

	core, err := auth.New(
		auth.WithSecret("a-test-signing-secret-long-enough-for-hs256"),
		auth.WithUserStore(m),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
		auth.WithBcryptCost(4),
		auth.WithPasswordVerifier(m.PasswordVerifier()),
	)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	const racers = 4
	var wg sync.WaitGroup
	errs := make([]error, racers)
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// One carrier per racer, because one carrier per REQUEST is what the
			// middleware installs. Sharing one here would test something the
			// deployment never does, and would hide a cross-request leak.
			ctx := ddbstore.WithMigrationScope(context.Background())
			_, _, err := core.Login(ctx, auth.LoginInput{Email: email, Password: password})
			errs[i] = err
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent login %d failed: %v; adoption is meant to be idempotent, not exclusive", i, err)
		}
	}

	// The account is migrated: the marker is gone and the local hash is the
	// proven password's.
	after, err := m.GetUserByEmail(t.Context(), email, "")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if markerRecorded(t, m, seeded.ID) {
		t.Error("the marker survived adoption; every failed login would keep asking the old directory forever")
	}
	if after.PasswordHash == "" {
		t.Fatal("the stored hash is still empty after adoption")
	}

	// And one more login proves the hash verifies AND that the source is no
	// longer consulted, which is how a migration ends for one person.
	_, verifyBefore := dir.counts()
	if _, _, err := core.Login(ddbstore.WithMigrationScope(t.Context()), auth.LoginInput{Email: email, Password: password}); err != nil {
		t.Fatalf("login after adoption: %v", err)
	}
	if _, verifyAfter := dir.counts(); verifyAfter != verifyBefore {
		t.Errorf("the source was consulted %d more times after adoption; a migrated account must stop paying for the migration",
			verifyAfter-verifyBefore)
	}
}
