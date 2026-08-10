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

	// MaxLinkedAccountsPerUser caps ListForUser, whose interface likewise has no
	// cursor. Defaults to DefaultMaxLinkedAccountsPerUser.
	MaxLinkedAccountsPerUser int

	// Logger receives the once-per-process warnings this store emits. Defaults
	// to slog.Default().
	Logger *slog.Logger
}

// Store implements, from awesome-go-auth's store.go: UserStore,
// UserAccountStore, UserPasswordStore, SessionStore, SessionLookupStore,
// SessionAdminStore, MagicLinkStore, SMSStore, EmailVerificationStore,
// EmailChangeStore and TOTPStore. The two OAuth stores of oauth.go are reached
// through Store.LinkedAccounts() and Store.PendingLinks(), because their
// interfaces both declare Save and Delete and no single type can satisfy both.
//
// The remaining optional interfaces land with their item types (data-model.md
// §1.4-§1.5) and are deliberately absent rather than stubbed, because the core
// discovers them by type assertion: a stub that returns "not implemented" would
// make Service advertise a feature that fails at runtime, where an absent method
// makes it return ErrFeatureNotSupported.
type Store struct {
	api   API
	table string
	index string
	now   func() time.Time

	multiTenant       bool
	consumeOnRead     bool
	ttlGrace          time.Duration
	maxSessions       int
	maxLinkedAccounts int

	log                  *slog.Logger
	degradedOnce         sync.Once
	unknownNamespaceOnce sync.Once
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
		api:               api,
		table:             opts.TableName,
		index:             opts.IndexName,
		now:               opts.Now,
		multiTenant:       opts.MultiTenant,
		consumeOnRead:     !opts.NonAtomicSingleUseTokens,
		ttlGrace:          opts.SessionTTLGrace,
		maxSessions:       opts.MaxSessionsPerUser,
		maxLinkedAccounts: opts.MaxLinkedAccountsPerUser,
		log:               opts.Logger,
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
	if s.maxLinkedAccounts == 0 {
		s.maxLinkedAccounts = DefaultMaxLinkedAccountsPerUser
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
		"POST /change-email/confirm fails rather than applying an empty address when no email change is pending; the reference would overwrite the address (data-model.md §4.1).",
		"POST /change-email/confirm fails if the pending address changed between reading the token and applying it, instead of applying the address it read (data-model.md §1.3 #22).",
		"GET /linked-accounts returns bindings ordered by provider then provider account id; the reference returns them in insertion order (data-model.md §1.5 #54).",
		"Re-linking a provider account that is already linked moves the binding and deletes the previous link id; the reference leaves the old id resolvable and still listed under its old owner (upstream nik2208/awesome-go-auth#37).",
		"POST /link-verify answers INVALID_LINK_TOKEN for an expired account-link token, where the reference answers LINK_TOKEN_EXPIRED: the store refuses to return an entry past its deadline, so the route's own expiry branch is never reached (data-model.md §4.5).",
	}
	if s.consumeOnRead {
		notes = append(notes,
			"Single-use tokens and SMS codes are consumed by the lookup itself, so a failure in the step that follows burns them and the user must request a new one (data-model.md §4.1). A code that does not match burns nothing.",
			"A replayed refresh token revokes the whole session, not just that token (data-model.md §4.3).",
			"An OAuth state nonce and an account-link token are consumed by PendingLinkStore.Get, so two callers racing on one link produce exactly one winner and the loser sees an invalid token (data-model.md §1.5 #57).",
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

// warnUnknownPendingLinkNamespace reports a PendingLinkStore key whose namespace
// this build does not recognise.
//
// It exists because the single-use classification in keys.go is a coupling to key
// builders the auth core does not export, so a core upgrade that adds a namespace
// cannot fail to compile and — since the unrecognised case is treated as
// re-readable — would not fail a test either. If the new namespace turns out to
// carry a credential, it is replayable, and this line is the only thing that says
// so. Once per process, like the rotation warning: it is a deployment-shaped
// problem, not a per-request one.
//
// Only the namespace is logged, never the rest of the key: see
// pendingLinkNamespace.
func (s *Store) warnUnknownPendingLinkNamespace(state string) {
	s.unknownNamespaceOnce.Do(func() {
		s.log.Warn("dynamodb: pending-link key in an unrecognised namespace, treated as re-readable; "+
			"if the auth core now issues a single-use credential under it, that credential can be replayed. "+
			"Add the prefix to pendingLinkSingleUsePrefixes (single-use) or "+
			"pendingLinkReReadablePrefixes (a stash entry) to silence this.",
			slog.String("namespace", pendingLinkNamespace(state)))
	})
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
