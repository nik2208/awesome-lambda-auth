package dynamodb

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// The migration marker, and why it travels on the request context rather than on
// auth.User.
//
// A deployment migrating off another identity provider marks every imported row,
// and the core's password-verifier seam requires a verifier to key on that
// marker before it does anything else — because the hook is reached by every
// login whose stored hash failed to verify, including OAuth-only accounts that
// never had a password, from an unauthenticated route
// (awesome-go-auth/password_verifier.go). So the marker has to reach the
// verifier, and the verifier is handed one thing: the auth.User the store
// returned.
//
// The obvious channel is auth.User.Metadata, and it is the wrong one.
// auth.NewPublicUser serialises Metadata (models.go), and GET <prefix>/me is the
// user object unwrapped, so a marker the verifier can read would be a marker the
// account holder can read — disclosing the source directory and the user pool
// id to anyone holding a session on a not-yet-migrated account. That is a real
// disclosure with a narrow window, and it would have had to be registered as a
// wire deviation and lived there forever.
//
// It is not necessary. The marker is on the PROFILE item, which the login path
// already reads, and Service.loginPassword passes ONE ctx value to both
// s.users.GetUserByEmail and s.verifyThroughPasswordVerifier -> verify
// (awesome-go-auth v0.8.0 login_2fa.go; login_2fa.go and password_verifier.go
// are byte-identical to v0.7.0, so the property did not arrive with the pin and
// does not depend on it). A ctx cannot be mutated by a callee, so the shape is
// the one rotationScope already uses for refresh rotation one file over: the
// HTTP layer installs an empty scope, the profile read fills it, the verifier
// consumes it. Nothing crosses through auth.User, so nothing can reach the wire.
//
// Two properties are deliberate and both are pinned by tests:
//
//   - It FAILS CLOSED. A verifier that finds no record for the user it was handed
//     answers "no marker" and therefore (false, false, nil). There is no fallback
//     to Metadata — a fallback would reintroduce exactly the disclosure this
//     exists to avoid, and would do it on the one path nobody tests twice.
//   - It is keyed by user id and consumed on read, like rotationScope. A record
//     left over from one user's read must never answer for another's, and a
//     second verifier call in one request must re-read rather than reuse.

// MigrationMarker names the directory an imported account came from. The zero
// value means "not imported", which is what every ordinary account is.
type MigrationMarker struct {
	// Source is the directory family, e.g. "cognito".
	Source string

	// Pool is the directory instance: the Cognito user pool id. It is compared
	// as well as Source, so a stack repointed at a second pool does not start
	// asking the new pool about accounts imported from the first.
	Pool string
}

// IsZero reports an absent marker.
func (m MigrationMarker) IsZero() bool { return m.Source == "" && m.Pool == "" }

// The marker's attribute and its two fields on the profile item. They are
// written by CreateMigratedUser, read by GetUserByID, and removed by
// UpdatePassword — and by nothing else, which is the whole lifecycle.
const (
	attrMigration = "migration"

	markerFieldSource = "source"
	markerFieldPool   = "pool"
)

// migrationScope is the request-scoped hand-off between the profile read and the
// password verifier. Single-slot and id-keyed, for the reasons rotationScope is.
type migrationScope struct {
	mu     sync.Mutex
	set    bool
	userID string
	marker MigrationMarker
}

type migrationScopeKey struct{}

// WithMigrationScope prepares ctx to carry the migration marker of whichever
// profile the request reads. The HTTP layer must call it once per request,
// before invoking the auth service; without it the verifier fails closed and no
// account migrates, which is why cmd/auth installs it whenever
// stores.migration is active and why reaching the verifier without one is
// warned about once per process.
//
// Calling it twice on the same ctx is a no-op, so nesting middleware is safe.
func WithMigrationScope(ctx context.Context) context.Context {
	if migrationScopeFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, migrationScopeKey{}, &migrationScope{})
}

func migrationScopeFrom(ctx context.Context) *migrationScope {
	scope, _ := ctx.Value(migrationScopeKey{}).(*migrationScope)
	return scope
}

func (s *migrationScope) record(userID string, marker MigrationMarker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userID = userID
	s.marker = marker
	s.set = true
}

func (s *migrationScope) take(userID string) (MigrationMarker, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.set || s.userID != userID {
		return MigrationMarker{}, false
	}
	marker := s.marker
	s.set = false
	s.marker = MigrationMarker{}
	return marker, true
}

// TakeMigrationMarker returns the marker recorded for userID during this
// request, and reports whether anything was recorded for that user at all.
//
// The two returns answer two different questions and the caller must keep them
// apart. (marker, true) with a zero marker means "this store read that user's
// profile and it carries no marker" — an ordinary account, and an ordinary
// refusal. (_, false) means "nothing was recorded for that user", which is
// either a missing scope or a path that reached a verifier without a profile
// read, and is a wiring fault rather than a statement about the account. Both
// have to end in the same answer to the client; only one is worth a log line.
func TakeMigrationMarker(ctx context.Context, userID string) (MigrationMarker, bool) {
	scope := migrationScopeFrom(ctx)
	if scope == nil {
		return MigrationMarker{}, false
	}
	return scope.take(userID)
}

// recordMigrationMarker files the marker read off a profile item, if this
// request is carrying a scope. A request that is not — every request on a
// deployment with no migration configured — pays one nil check.
func recordMigrationMarker(ctx context.Context, userID string, marker MigrationMarker) {
	if scope := migrationScopeFrom(ctx); scope != nil {
		scope.record(userID, marker)
	}
}

// RecordMigrationMarkerForTest files a marker as a profile read would have.
//
// It exists for the verifier's own tests, one package up, which have to exercise
// the gate for a marker that is present, absent, or another pool's, and which
// cannot construct any of those by hand any more — there is no field on
// auth.User to set, which is the whole point. Making them drive a real DynamoDB
// write for each case would test this store rather than the gate.
//
// Named ForTest and documented as such rather than hidden behind a build tag:
// the function is three lines and harmless (it writes to a carrier the caller
// owns and nothing reads unless a verifier runs on the same request), and a
// production caller reaching for it would be doing something visible in review.
func RecordMigrationMarkerForTest(ctx context.Context, userID string, marker MigrationMarker) {
	recordMigrationMarker(ctx, userID, marker)
}

// markerFromItem decodes the profile's `migration` attribute.
//
// It is deliberately NOT part of userFromItem: the point of this whole file is
// that the marker never touches auth.User, and a decoder that filled a field on
// one would be one refactor away from putting it back on the wire.
func markerFromItem(m map[string]types.AttributeValue) MigrationMarker {
	av, ok := m[attrMigration].(*types.AttributeValueMemberM)
	if !ok {
		return MigrationMarker{}
	}
	marker := MigrationMarker{}
	if s, ok := av.Value[markerFieldSource].(*types.AttributeValueMemberS); ok {
		marker.Source = s.Value
	}
	if s, ok := av.Value[markerFieldPool].(*types.AttributeValueMemberS); ok {
		marker.Pool = s.Value
	}
	return marker
}

// markerItem encodes a marker for the profile item, or nil for a zero one.
//
// A marker with neither field is dropped rather than written empty: the omission
// rule in §5 is what lets the REMOVE in UpdatePassword and an
// attribute_not_exists condition mean what they say, and a present-but-empty
// marker would be a row that reads as mid-migration forever while naming no
// directory to ask.
func markerItem(marker MigrationMarker) types.AttributeValue {
	if marker.IsZero() {
		return nil
	}
	fields := map[string]types.AttributeValue{}
	if marker.Source != "" {
		fields[markerFieldSource] = avS(marker.Source)
	}
	if marker.Pool != "" {
		fields[markerFieldPool] = avS(marker.Pool)
	}
	return &types.AttributeValueMemberM{Value: fields}
}

// WarnNoMigrationScope reports, once per process, that a verifier was reached
// with no marker filed for the user it was handed.
//
// Exported because the verifier that discovers it lives in
// internal/store/migrating, one package up, and the warning belongs to the store
// that would have done the filing — it is the same fault warnDegradedRotation
// reports for the other carrier, and an operator should find the two beside each
// other rather than in two vocabularies.
//
// Once and not per request: the cause is a composition that never installs the
// middleware, so it is true for every request or for none, and a line per login
// would be the loudest thing in the log of a deployment that is also not
// migrating anybody. The same bargain warnDegradedRotation strikes.
func (s *Store) WarnNoMigrationScope() {
	s.migrationScopeOnce.Do(func() {
		s.log.Warn("a migration password verifier was reached with no migration scope on the request context; " +
			"no account can migrate until the HTTP layer calls dynamodb.WithMigrationScope once per request " +
			"(cmd/auth installs it whenever stores.migration is active)")
	})
}
