// Package dynamodb implements the awesome-go-auth store interfaces on a single
// DynamoDB table, following docs/spec/data-model.md.
//
// The AWS SDK is confined to this package and to internal/integration/aws: the
// auth core stays cloud-agnostic, so nothing here leaks upward except the
// interfaces the core already declares.
//
// Two rules shape every method below and are worth stating once rather than
// repeating at each call site:
//
//   - No constraint is enforced by reading and then writing. Uniqueness,
//     single-use and rotation are all ConditionExpressions, so two concurrent
//     invocations of the same Lambda cannot both win.
//   - Tenant isolation lives in the partition key, never in a FilterExpression.
//     A query for tenant A physically cannot touch tenant B's partition.
package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// API is the slice of the DynamoDB client this store actually uses. Taking an
// interface rather than *dynamodb.Client keeps the fault-injection tests honest
// and documents the blast radius of the IAM policy the Lambda needs.
type API interface {
	GetItem(ctx context.Context, in *awsddb.GetItemInput, optFns ...func(*awsddb.Options)) (*awsddb.GetItemOutput, error)
	PutItem(ctx context.Context, in *awsddb.PutItemInput, optFns ...func(*awsddb.Options)) (*awsddb.PutItemOutput, error)
	UpdateItem(ctx context.Context, in *awsddb.UpdateItemInput, optFns ...func(*awsddb.Options)) (*awsddb.UpdateItemOutput, error)
	DeleteItem(ctx context.Context, in *awsddb.DeleteItemInput, optFns ...func(*awsddb.Options)) (*awsddb.DeleteItemOutput, error)
	Query(ctx context.Context, in *awsddb.QueryInput, optFns ...func(*awsddb.Options)) (*awsddb.QueryOutput, error)
	TransactWriteItems(ctx context.Context, in *awsddb.TransactWriteItemsInput, optFns ...func(*awsddb.Options)) (*awsddb.TransactWriteItemsOutput, error)
	BatchGetItem(ctx context.Context, in *awsddb.BatchGetItemInput, optFns ...func(*awsddb.Options)) (*awsddb.BatchGetItemOutput, error)
	BatchWriteItem(ctx context.Context, in *awsddb.BatchWriteItemInput, optFns ...func(*awsddb.Options)) (*awsddb.BatchWriteItemOutput, error)
}

// Defaults for Options. Exported so the config layer can document them without
// duplicating the numbers.
const (
	// DefaultIndexName is the single sparse GSI (data-model.md §2.1).
	DefaultIndexName = "GSI1"

	// DefaultSessionTTLGrace keeps a session item alive past its expiry so a
	// replayed refresh token still finds the family to revoke (§4.5).
	DefaultSessionTTLGrace = 24 * time.Hour

	// DefaultMaxSessionsPerUser caps ListSessionsForUser, whose interface has no
	// cursor parameter (§8.6). One user reaching four digits of live sessions is
	// an incident, not a page to render, so the store refuses rather than
	// silently truncating.
	DefaultMaxSessionsPerUser = 1000
)

// Options configures a Store. TableName is the only required field.
type Options struct {
	// TableName is the single table every item lives in.
	TableName string

	// IndexName is the sparse by-owner GSI. Defaults to DefaultIndexName.
	IndexName string

	// Now is the clock. Injected so tests can pin expiries; defaults to
	// time.Now.
	Now func() time.Time

	// MultiTenant rejects an empty tenant id at the store boundary. With it
	// off, "" is an ordinary tenant value and maps to its own partition — which
	// is exactly what the auth core does (memory_store.go:32-34), so a
	// single-tenant deployment needs no special case.
	MultiTenant bool

	// NonAtomicSingleUseTokens restores the reference implementation's
	// read-then-clear for single-use tokens, for strict-parity testing. The
	// default (false) makes GetUserBy*TokenHash the consuming write, so two
	// callers racing on the same link cannot both pass (§4.1). Stated as an
	// opt-out because the safe behaviour must be what a zero-value Options
	// gives you.
	NonAtomicSingleUseTokens bool

	// SessionTTLGrace defaults to DefaultSessionTTLGrace.
	SessionTTLGrace time.Duration

	// MaxSessionsPerUser defaults to DefaultMaxSessionsPerUser.
	MaxSessionsPerUser int

	// Logger receives the once-per-process warnings this store emits. Defaults
	// to slog.Default().
	Logger *slog.Logger
}

// Store implements, from awesome-go-auth's store.go: UserStore,
// UserAccountStore, UserPasswordStore, SessionStore, SessionLookupStore and
// SessionAdminStore. The remaining optional interfaces land with their item
// types (data-model.md §1.3-§1.5) and are deliberately absent rather than
// stubbed, because the core discovers them by type assertion: a stub that
// returns "not implemented" would make Service advertise a feature that fails
// at runtime, where an absent method makes it return ErrFeatureNotSupported.
type Store struct {
	api   API
	table string
	index string
	now   func() time.Time

	multiTenant   bool
	consumeOnRead bool
	ttlGrace      time.Duration
	maxSessions   int

	log          *slog.Logger
	degradedOnce sync.Once
}

// New validates opts and returns a Store. It performs no I/O: the table is
// expected to exist, because creating it is an infrastructure concern and a
// cold-started Lambda must not pay a DescribeTable on the login path.
func New(api API, opts Options) (*Store, error) {
	if api == nil {
		return nil, errors.New("dynamodb: api client is required")
	}
	if opts.TableName == "" {
		return nil, errors.New("dynamodb: table name is required")
	}
	s := &Store{
		api:           api,
		table:         opts.TableName,
		index:         opts.IndexName,
		now:           opts.Now,
		multiTenant:   opts.MultiTenant,
		consumeOnRead: !opts.NonAtomicSingleUseTokens,
		ttlGrace:      opts.SessionTTLGrace,
		maxSessions:   opts.MaxSessionsPerUser,
		log:           opts.Logger,
	}
	if s.index == "" {
		s.index = DefaultIndexName
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.ttlGrace == 0 {
		s.ttlGrace = DefaultSessionTTLGrace
	}
	if s.maxSessions == 0 {
		s.maxSessions = DefaultMaxSessionsPerUser
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	return s, nil
}

// CompatibilityNotes lists the deviations from the reference implementation that
// are visible on the wire, so the deployment can surface them instead of
// letting a caller discover them. Each entry cites the section that argues it.
func (s *Store) CompatibilityNotes() []string {
	notes := []string{
		"POST /sessions/cleanup always reports deleted:0 — expiry is DynamoDB TTL, which produces no count (data-model.md §4.5).",
		"GET /sessions returns sessions oldest-first by creation time; the reference returns them in unspecified map order (data-model.md §5).",
		"Revoking an already-revoked session keeps the first revocation's timestamp and reason instead of overwriting them (data-model.md §4.4).",
	}
	if s.consumeOnRead {
		notes = append(notes,
			"Single-use tokens are consumed by the lookup itself, so a failure in the step that follows burns the token and the user must request a new one (data-model.md §4.1).",
			"A replayed refresh token revokes the whole session, not just that token (data-model.md §4.3).",
		)
	}
	return notes
}

// nowUTC is the single clock read per operation. Every timestamp the store
// writes comes from here so an item's attributes cannot disagree with each
// other by a scheduling delay.
func (s *Store) nowUTC() time.Time {
	return s.now().UTC()
}

// transactionConflictAttempts bounds the retry below. Four is enough for the
// contention this store actually sees — the transactional paths are per-login or
// rarer (data-model.md §6.3) — and small enough to stay well inside a Lambda
// deadline.
const transactionConflictAttempts = 4

// transactWrite runs a transaction and retries the one cancellation reason that
// is transient: TransactionConflict, meaning another writer held one of the same
// items and no ConditionExpression was ever evaluated.
//
// Nothing else retries it. The SDK's standard retryer covers
// TransactionInProgressException but not TransactionCanceledException
// (aws-sdk-go-v2/aws/retry/standard.go:76), so without this the constraint that
// every conditional write in this package exists to enforce would go unanswered
// exactly when it matters most — under the concurrency that produces the
// conflict. Two registrations of one address would then report an opaque error
// instead of ErrUserExists, and a losing rotation would never reach
// classifyRotationLoss and so would never revoke the replayed family.
//
// A cancelled transaction writes nothing, so a retry is a fresh attempt rather
// than a partial one, and every condition in this package is either idempotent
// for its own caller or decides the outcome on the retry.
func (s *Store) transactWrite(ctx context.Context, in *awsddb.TransactWriteItemsInput) error {
	for attempt := 0; ; attempt++ {
		_, err := s.api.TransactWriteItems(ctx, in)
		if err == nil {
			return nil
		}
		if attempt == transactionConflictAttempts-1 || !isTransactionConflict(err) {
			return err
		}
		if sleepErr := sleepCtx(ctx, backoff(attempt)); sleepErr != nil {
			return sleepErr
		}
	}
}

func (s *Store) warnDegradedRotation() {
	s.degradedOnce.Do(func() {
		s.log.Warn("dynamodb: refresh rotation is running without a precondition; " +
			"install the rotation scope per request (dynamodb.WithRotationScope) or use RotateSession. " +
			"Concurrent refreshes of one token will both succeed and the replay will only be detected on the next use.")
	})
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("dynamodb: %s: %w", op, err)
}
