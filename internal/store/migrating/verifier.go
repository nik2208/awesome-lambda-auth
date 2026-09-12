package migrating

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	auth "github.com/nik2208/awesome-go-auth"

	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// PasswordVerifier returns the hook cmd/auth hands to auth.WithPasswordVerifier.
//
// ── the contract it is written against ───────────────────────────────────────
//
// The core consults it for a user whose STORED HASH DID NOT VERIFY the password
// a login request carried, and for no other user. A migrated account stops
// reaching it the moment its local hash lands, and a deployment that has
// finished migrating pays nothing per login
// (awesome-go-auth/password_verifier.go).
//
// The three answers, and what this implementation does with each:
//
//   - (false, false, nil) — not the password. The login answers
//     ErrInvalidCredentials, the identical sentinel and therefore the identical
//     401 body that a wrong local password produces. This is the answer for
//     every account with no marker, for every account the pool has never heard
//     of, and for every refusal the pool makes.
//   - (true, true, nil) — the password, adopt it. The core hashes it at
//     Config.BcryptCost and writes it through UserPasswordStore.UpdatePassword,
//     which on this store is also the write that drops the marker
//     (internal/store/dynamodb/tokens.go). After it, this hook is never reached
//     for that user again, which is how one person's migration ends.
//   - a non-nil error — a failure to decide. The login fails closed and answers
//     a generic 500. Reserved, deliberately, for "the pool did not answer": a
//     throttle, a timeout, a misconfigured app client. Every outcome that means
//     "this account cannot prove this password here" is the first answer, not
//     this one, because a decision rendered as an error would turn an ordinary
//     failed login into a 500 that a client could count.
//
// ── the gate, which is a requirement and not a style note ────────────────────
//
// The first thing this does is take the marker the profile read filed on this
// request's context and answer (false, false, nil) if it is absent or names
// another pool. Nothing before that line touches the network, the password or
// the address. Upstream requires it and gives two reasons, both of which are
// about what the hook is reachable by rather than about what it is for:
//
//   - It is reached by every login whose stored hash failed to verify. That
//     includes every account that never had a password — OAuth-only,
//     magic-link-only — which carries an empty hash and therefore arrives here
//     carrying whatever plaintext the request held. The reference refuses those
//     before it compares anything (local.strategy.ts:23-25).
//   - It sits on an unauthenticated route. Without the gate, POST /login is an
//     amplifier aimed at Cognito's lockout counters for every address an
//     attacker cares to name.
//
// And a third, which upstream states as the sharpest edge on the seam: adoption
// overwrites WHATEVER hash was stored, not only an empty one. A verifier that
// answered ok for a live local account would replace that account's working
// password with whatever the request carried. The marker gate is what blunts
// that, so it is written as the first statement of the function and every return
// above it is a refusal.
//
// ── what is bounded, and what is not ─────────────────────────────────────────
//
// The call that survives the gate is rate-limited per user and globally
// (limiter.go), which upstream also requires in so many words. Over budget the
// answer is (false, false, nil): the same answer a wrong password gets, so
// engaging the limiter is not observable.
//
// Latency is not equalised, and upstream says that is the host's problem rather
// than the library's. A marked account whose hash does not verify pays a bcrypt
// compare plus a network round trip; an unmarked one pays the compare. The gate
// is what keeps that to the accounts actually being migrated, and the limiter is
// what caps how much of it an attacker can buy.
//
// ── where the marker comes from, and why it fails closed ─────────────────────
//
// Not from `user`. auth.NewPublicUser serialises everything on auth.User and
// GET <prefix>/me is that projection unwrapped, so a marker carried there would
// name the source directory and the user pool id to whoever holds a session on a
// not-yet-migrated account. It comes from the request context instead, where the
// store's profile read filed it — one read, no extra round trip, and nothing
// that a response could serialise. internal/store/dynamodb/migration.go argues
// the carrier and cites the core line that makes it correct: loginPassword
// passes one ctx value to both GetUserByEmail and the verifier.
//
// The consequence is a rule with no exception: no record for this user id means
// NO MARKER, which means (false, false, nil). It does not mean "look somewhere
// else". A fallback to user.Metadata would be the disclosure coming back through
// the one path nobody tests twice, and a fallback to "assume migrating" would
// hand an unauthenticated route to the amplifier the gate exists to prevent. The
// cost of failing closed is that a composition which forgets the middleware
// migrates nobody — loudly, because the store warns once per process about
// exactly that.
//
// ── what a client can see ────────────────────────────────────────────────────
//
// Nothing. That is a requirement of the seam — upstream says a configured
// verifier must leave POST /login answering exactly what it answered before,
// same statuses, same codes, same bodies, and that anything a client could use
// to tell one apart is a wire deviation. Every path below returns one of the
// three answers above and writes nothing to the response, and cmd/auth pins the
// property directly: TestLoginIsByteIdenticalWithAVerifierConfigured drives the
// same requests through two apps and compares the responses. With the marker off
// auth.User there is no product deviation left to register for any of this.
func (m *MigratingUserStore) PasswordVerifier() auth.PasswordVerifier {
	ref := m.ref()

	return func(ctx context.Context, user auth.User, password string) (bool, bool, error) {
		// The gate. First statement, no exceptions, nothing above it.
		marker, recorded := ddbstore.TakeMigrationMarker(ctx, user.ID)
		if !recorded {
			// Nothing was filed for this user on this request: either no scope was
			// installed, or the verifier was reached by a path that did not read a
			// profile. Both are wiring faults rather than statements about the
			// account, and both answer exactly what an unmarked account answers.
			m.Store.WarnNoMigrationScope()
			return false, false, nil
		}
		if !ref.Matches(marker) {
			return false, false, nil
		}
		// An empty password is never adopted by the core — a bcrypt hash of ""
		// would make empty-password login succeed forever and would close the
		// passwordless initial-password path (password_verifier.go) — so the
		// round trip could not change the outcome and is not made.
		if password == "" {
			return false, false, nil
		}
		// The subject is the user id and not the address. The id is stable, it is
		// what the marker is attached to, and it cannot be varied by the request:
		// an attacker who knows one account's address cannot spread their budget
		// across spellings of it, because the address they sent has already been
		// resolved to this one row before the hook is reached.
		if !m.verifyLimit.allow(user.ID) {
			m.log.Warn("migration password verifier refused a login without asking the source: the rate limit is spent",
				slog.String("userId", user.ID),
				slog.String("source", m.source))
			return false, false, nil
		}

		// The address the pool is asked about is the STORED one, not the one the
		// request carried. They are the same address — the store resolved the
		// request's to this row — but only the stored one has been through the
		// uniqueness item, so using it means no value taken straight from a
		// request body is ever forwarded to the source.
		err := m.directory.VerifyPassword(ctx, user.Email, password)
		switch {
		case err == nil:
			return true, true, nil

		case errors.Is(err, awsintegration.ErrCognitoPasswordRejected),
			errors.Is(err, awsintegration.ErrCognitoUserNotFound),
			errors.Is(err, awsintegration.ErrCognitoUserNotConfirmed),
			errors.Is(err, awsintegration.ErrCognitoPasswordResetRequired),
			errors.Is(err, awsintegration.ErrCognitoChallenge):
			// Every one of these is a decision: the source will not sign this
			// person in with this password either. Rendering any of them as an
			// error would answer 500 where the route must answer 401, and would
			// make the five distinguishable from each other by a client with a
			// stopwatch and a status code. They are logged, because an operator
			// watching a migration needs to know the difference between "people
			// are typing the wrong password" and "this pool forces a reset on
			// everybody", and the wire says nothing about either.
			m.log.Info("migration password verifier: the source refused the credential",
				slog.String("userId", user.ID),
				slog.String("source", m.source),
				slog.String("outcome", err.Error()))
			return false, false, nil

		default:
			// The pool did not answer: a throttle, a timeout, an app client
			// configured with a secret. Fail closed, which the core turns into a
			// generic 500 — the same 500 it produces for a store failure, with no
			// code or body of its own.
			//
			// %w and not %v, unlike the core's own wrapping rule: nothing in this
			// package's error chain is a sentinel auth.HTTPErrorFor maps, so
			// keeping the chain leaks nothing and lets a log tell a throttle from
			// a misconfiguration. The core wraps whatever comes back with %v on
			// its way out, which is where the leak would otherwise be.
			return false, false, fmt.Errorf("migrating: the source directory could not decide: %w", err)
		}
	}
}
