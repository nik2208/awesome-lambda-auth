package main

import (
	"fmt"
	"log/slog"
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
	"github.com/nik2208/awesome-lambda-auth/internal/store/migrating"
)

// The migration block: where this deployment's users are coming from, while
// they are still coming. `stores.migration` is the X1 block of the schema, and
// unlike every block before it there was nothing in internal/config/phases.go to
// stop refusing — it is new here, it is wired by the same change that declares
// it, and it must never be added to unwiredDomains().
//
// ── what it wires, and in what order ─────────────────────────────────────────
//
// Three things, attaching at three different seams, which is why this block is
// the only one that is not a single somethingOptions(cfg) beside claims.go and
// oauth.go:
//
//   - The user store is WRAPPED, by migrationWiring, before coreOptions hands it
//     to auth.WithUserStore. internal/store/migrating adds the dual-read
//     fall-through to GetUserByEmail and nothing else; every other method, and
//     every optional interface the core discovers by type assertion, is the
//     embedded store's by promotion.
//   - One core option is CONTRIBUTED, by migrationOptions, as an ordinary entry
//     in coreOptionSets: auth.WithPasswordVerifier, and only when an app client
//     id is configured. Without one the deployment still imports and still
//     dual-reads; it just never asks the old directory about a password, which
//     is exactly the posture of a stack whose bulk import is finished.
//   - A per-request carrier is INSTALLED, by migrationScopeMiddleware, so the
//     marker can travel from the store's profile read to the verifier without
//     ever being a field on auth.User.
//
// ── why this adds no wire deviation ──────────────────────────────────────────
//
// The seam upstream is deliberately not one, and the file that declares it says
// why at length and then says "keep it that way": with a verifier configured,
// POST <prefix>/login answers exactly what it answered before — the same 200
// token body, the same 401 INVALID_CREDENTIALS from the same sentinel, the same
// generic 500 — on that route and every other. Nothing in this product's half
// adds a status, a code or a body field either: a fall-through that fails
// returns the original ErrUserNotFound, a verifier that refuses returns the same
// (false, false, nil) an unmarked account gets, and a limiter that engages is
// indistinguishable from a wrong password.
//
// The last thing that could have been visible was the marker itself, because
// auth.NewPublicUser serialises auth.User.Metadata and GET <prefix>/me is that
// projection unwrapped. It is not visible, because the marker never goes there:
// the carrier is what buys that, and it is the reason this block registers
// nothing in WireDeviations(). app_test.go's
// TestLoginIsByteIdenticalWithAVerifierConfigured and migration_test.go's
// TestMigrationDisclosesNothingOnTheWire are what keep both halves true rather
// than merely intended.
//
// What it does change, and what no test asserts, is latency: a marked account
// whose stored hash does not verify now pays a network round trip on an
// unauthenticated route. Upstream states the same thing about the seam itself
// and concludes that equalising it is the host's job; what this product does
// about it is gate it on the marker, rate-limit what survives the gate, and
// default the whole block off. docs/cognito-comparison.md §4 says so in the
// operator's words.

// migrationScopeMiddleware installs the per-request carrier the migration marker
// travels on, the sibling of rotationScopeMiddleware and installed for the same
// structural reason: a ctx cannot be mutated by a callee, so the HTTP layer has
// to put an empty scope on it and let the store fill it and the verifier consume
// it.
//
// Without it the verifier fails closed and no account migrates — deliberately,
// because the alternatives are worse: reading the marker off auth.User instead
// would put it back on the wire, and assuming "migrating" would hand an
// unauthenticated route to the amplifier the marker gate exists to prevent. The
// store warns once per process when it happens, so a composition that forgets
// this says so rather than quietly migrating nobody.
func migrationScopeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(ddbstore.WithMigrationScope(r.Context())))
	})
}

// migrationOptions is the coreOptionSets entry: the password-verifier seam, and
// only when an app client id makes it usable.
//
// It takes the user store rather than a verifier because by the time
// coreOptionSets runs, `users` IS the wrapper migrationWiring installed, and the
// verifier is a method on it. Deriving it here rather than threading it through
// keeps coreOptionSets' signature the shape the other six sets need.
func migrationOptions(cfg *config.Config, users auth.UserStore) ([]auth.Option, error) {
	if !cfg.Stores.Migration.VerifierConfigured() {
		return nil, nil
	}
	store, ok := users.(*migrating.MigratingUserStore)
	if !ok {
		// Unreachable through New, which wraps before it builds the option sets.
		// Reaching it means the two halves of this file were called out of order,
		// which would otherwise surface as a deployment that imports users and
		// then never migrates one.
		return nil, fmt.Errorf("stores.migration: the password verifier needs the migrating user store, and the composition produced a %T", users)
	}
	return []auth.Option{auth.WithPasswordVerifier(store.PasswordVerifier())}, nil
}

// migrationWiring returns the user store the core should be given. With the
// block unconfigured it returns its argument, having constructed nothing.
func migrationWiring(cfg *config.Config, users auth.UserStore, injected awsintegration.CognitoDirectory, log *slog.Logger) (auth.UserStore, error) {
	m := cfg.Stores.Migration
	if !m.Active() {
		return users, nil
	}

	// RS-13 has already refused every driver that cannot hold the marker, so
	// reaching here with anything but the DynamoDB store means the store factory
	// was injected — which is a test, and a test that has wired a composition the
	// binary would never build should be told so rather than be handed a
	// migration that silently does nothing.
	inner, ok := users.(*ddbstore.Store)
	if !ok {
		return nil, fmt.Errorf("stores.migration: the migration block needs the dynamodb user store, and the configured store factory produced a %T", users)
	}

	directory := injected
	if directory == nil {
		built, err := awsintegration.NewCognitoDirectory(awsintegration.CognitoOptions{
			UserPoolID: m.UserPoolID,
			ClientID:   m.ClientID,
			Region:     m.Region,
		})
		if err != nil {
			return nil, fmt.Errorf("stores.migration: %w", err)
		}
		directory = built
	}

	store, err := migrating.New(migrating.Options{
		Inner:      inner,
		Directory:  directory,
		Source:     m.Source,
		UserPoolID: m.UserPoolID,
		DualRead:   m.DualRead(),
		Logger:     log,
	})
	if err != nil {
		return nil, fmt.Errorf("stores.migration: %w", err)
	}

	// Announced at cold start, beside the deviation registers, for the same
	// reason they are: a deployment that is forwarding passwords to somebody
	// else's directory on its login path should say so in its own log rather
	// than leave it to be reconstructed from a Cognito bill. The pool id is not
	// a secret — it is in every Cognito-hosted login URL — and it is the one
	// value that makes the line actionable.
	log.Info("user migration is active",
		slog.String("source", m.Source),
		slog.String("userPoolId", m.UserPoolID),
		slog.String("mode", m.Mode),
		slog.Bool("passwordVerifier", m.VerifierConfigured()))
	if !m.VerifierConfigured() {
		log.Info("user migration has no app client id, so no login will ask the source about a password",
			slog.String("path", "stores.migration.clientId"))
	}

	return store, nil
}
