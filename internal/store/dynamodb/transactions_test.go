package dynamodb

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// TransactionConflict is the cancellation reason real DynamoDB returns when two
// transactions touch one item at the same instant. DynamoDB Local serialises
// instead and never produces it, so the only way to cover the paths that matter
// most under concurrency is to inject it.

// flakyTransactAPI cancels the first n transactions with TransactionConflict and
// then delegates to the real client.
type flakyTransactAPI struct {
	API
	conflicts atomic.Int32
	calls     atomic.Int32
}

func (f *flakyTransactAPI) TransactWriteItems(ctx context.Context, in *awsddb.TransactWriteItemsInput, optFns ...func(*awsddb.Options)) (*awsddb.TransactWriteItemsOutput, error) {
	f.calls.Add(1)
	if f.conflicts.Add(-1) >= 0 {
		return nil, cancelledWith(reasonTransactionConflict)
	}
	return f.API.TransactWriteItems(ctx, in, optFns...)
}

// refusingTransactAPI always reports a failed condition on the second operation,
// which is what a real duplicate registration looks like.
type refusingTransactAPI struct {
	API
	calls atomic.Int32
}

func (f *refusingTransactAPI) TransactWriteItems(context.Context, *awsddb.TransactWriteItemsInput, ...func(*awsddb.Options)) (*awsddb.TransactWriteItemsOutput, error) {
	f.calls.Add(1)
	none := "None"
	failed := reasonConditionFailed
	return nil, &types.TransactionCanceledException{
		Message:             aws.String("Transaction cancelled, please refer cancellation reasons for specific reasons"),
		CancellationReasons: []types.CancellationReason{{Code: &none}, {Code: &failed}},
	}
}

func cancelledWith(codes ...string) error {
	reasons := make([]types.CancellationReason, 0, len(codes))
	for _, c := range codes {
		code := c
		reasons = append(reasons, types.CancellationReason{Code: &code})
	}
	return &types.TransactionCanceledException{
		Message:             aws.String("Transaction cancelled, please refer cancellation reasons for specific reasons"),
		CancellationReasons: reasons,
	}
}

// TestATransactionConflictIsRetriedUntilAConditionDecides is the point of the
// retry: a conflict means no ConditionExpression was reached, so it answers
// nothing. Reported as-is it would turn "that address is taken" into an opaque
// error precisely when two people are registering it at once.
func TestATransactionConflictIsRetriedUntilAConditionDecides(t *testing.T) {
	t.Parallel()
	base, client := newStore(t)
	flaky := &flakyTransactAPI{API: client}
	store, err := New(flaky, Options{TableName: base.table, Logger: base.log})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ctx := context.Background()

	u := sampleUser("acme")
	flaky.conflicts.Store(2)
	if _, err := store.CreateUser(ctx, u); err != nil {
		t.Fatalf("a conflict must be retried, not reported: %v", err)
	}
	if got := flaky.calls.Load(); got != 3 {
		t.Errorf("transaction attempted %d times, want 3", got)
	}

	// Now the same address again, still behind conflicts: the retry has to reach
	// the condition and return the answer the condition gives.
	flaky.calls.Store(0)
	flaky.conflicts.Store(2)
	dup := sampleUser("acme")
	dup.Email = u.Email
	if _, err := store.CreateUser(ctx, dup); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("err = %v, want ErrUserExists", err)
	}
}

// TestATransactionConflictIsRetriedOnRotation: a losing rotation must still reach
// classifyRotationLoss, because that is where the replayed family gets revoked. A
// conflict swallowing the answer would leave the family alive.
func TestATransactionConflictIsRetriedOnRotation(t *testing.T) {
	t.Parallel()
	base, client := newStore(t)
	flaky := &flakyTransactAPI{API: client}
	store, err := New(flaky, Options{TableName: base.table, Logger: base.log})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	next := sess
	next.RefreshTokenHash = hashOf(uniqueID("refresh"))
	flaky.conflicts.Store(2)
	if err := store.RotateSession(ctx, sess.ID, sess.RefreshTokenHash, next); err != nil {
		t.Fatalf("rotation behind a conflict: %v", err)
	}

	// A stale precondition behind conflicts still has to be classified as a replay
	// and still has to kill the family.
	flaky.conflicts.Store(2)
	stale := sess
	stale.RefreshTokenHash = hashOf(uniqueID("refresh"))
	if err := store.RotateSession(ctx, sess.ID, sess.RefreshTokenHash, stale); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
	raw := rawItem(t, client, base.table, sessionPK(sess.ID), skSession)
	if got := getS(raw, attrRevokedReason); got != reasonReplay {
		t.Errorf("revokedReason = %q, want %q", got, reasonReplay)
	}
}

// TestAFailedConditionIsNotRetried: the condition is the answer, so retrying it
// would at best waste a round trip and at worst return a different answer than
// the one the constraint already gave.
func TestAFailedConditionIsNotRetried(t *testing.T) {
	t.Parallel()
	refusing := &refusingTransactAPI{}
	store, err := New(refusing, Options{TableName: "t"})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.CreateUser(context.Background(), sampleUser("acme")); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("err = %v, want ErrUserExists", err)
	}
	if got := refusing.calls.Load(); got != 1 {
		t.Errorf("transaction attempted %d times, want 1", got)
	}
}

// TestAPersistentConflictIsReportedNotMisclassified: when retrying does not help,
// the caller must hear that the write was cancelled — never that the address was
// taken or that the session was replayed.
func TestAPersistentConflictIsReportedNotMisclassified(t *testing.T) {
	t.Parallel()
	flaky := &flakyTransactAPI{}
	flaky.conflicts.Store(1 << 20)
	store, err := New(flaky, Options{TableName: "t"})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ctx := context.Background()

	got := func(err error) string {
		if err == nil {
			return "<nil>"
		}
		return err.Error()
	}

	err = func() error { _, e := store.CreateUser(ctx, sampleUser("acme")); return e }()
	if err == nil || errors.Is(err, auth.ErrUserExists) {
		t.Errorf("CreateUser: %s, want a reported cancellation", got(err))
	}
	if !strings.Contains(got(err), "TransactionCanceled") {
		t.Errorf("CreateUser error hides the cause: %s", got(err))
	}
	if n := flaky.calls.Load(); n != transactionConflictAttempts {
		t.Errorf("attempted %d times, want the %d-attempt bound", n, transactionConflictAttempts)
	}

	u := sampleUser("acme")
	sess := sampleSession(u)
	next := sess
	next.RefreshTokenHash = hashOf("new")
	rotateErr := store.RotateSession(ctx, sess.ID, sess.RefreshTokenHash, next)
	if errors.Is(rotateErr, auth.ErrSessionNotFound) || errors.Is(rotateErr, auth.ErrSessionRevoked) {
		t.Errorf("RotateSession: %s, want a reported cancellation rather than a replay verdict", got(rotateErr))
	}
}
