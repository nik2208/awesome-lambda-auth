package dynamodb

import (
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ErrUserNotFound is returned wherever the in-memory reference returns a bare
// errors.New("user not found") (memory_store.go:57, :70, :81, …). The message is
// copied verbatim so nothing that surfaces err.Error() changes on the wire; the
// sentinel exists so port code can match with errors.Is, which the reference
// cannot.
var ErrUserNotFound = errors.New("user not found")

// ErrNoPendingEmailChange means ApplyEmailChange was called with no pending
// address on the profile. It is a fault rather than an authentication outcome:
// the core only calls it after consuming an email-change token, and issuing that
// token writes the address in the same conditional update, so reaching it means
// the two got out of step.
//
// The reference has no counterpart — MemoryUserStore promotes the empty string
// and orphans the uniqueness item (memory_store.go:376) — so this is a
// deliberate divergence in favour of refusing.
var ErrNoPendingEmailChange = errors.New("dynamodb: no pending email change to apply")

// ErrResultTooLarge means a list method's result exceeded its cap. The
// interfaces it applies to take no cursor (data-model.md §8.6), so the store's
// only honest options are to refuse or to truncate silently; it refuses.
var ErrResultTooLarge = errors.New("dynamodb: result set exceeds the configured cap")

// isConditionFailed reports whether a single-item conditional write lost.
func isConditionFailed(err error) bool {
	var cf *types.ConditionalCheckFailedException
	return errors.As(err, &cf)
}

// conditionFailedItem returns the pre-image DynamoDB attached to a failed
// conditional write when ReturnValuesOnConditionCheckFailure was set. An empty
// map means the item did not exist, which is how "no such session" is told apart
// from "already revoked" without a second read.
func conditionFailedItem(err error) (map[string]types.AttributeValue, bool) {
	var cf *types.ConditionalCheckFailedException
	if !errors.As(err, &cf) {
		return nil, false
	}
	return cf.Item, true
}

// cancellation reasons DynamoDB reports inside TransactionCanceledException.
const (
	reasonConditionFailed = "ConditionalCheckFailed"

	// reasonTransactionConflict means another transaction, or a bare write, was
	// operating on one of these items. It is transient and says nothing about the
	// constraint: no ConditionExpression was reached.
	reasonTransactionConflict = "TransactionConflict"
)

// isTransactionConflict reports whether a cancellation was caused only by
// concurrent access to one of the items.
//
// A conflict alongside a genuine condition failure is not one: the condition
// already decided the outcome, and retrying would either return the same answer
// or, worse, return a different one. Only a cancellation in which nothing failed
// a condition is worth attempting again.
func isTransactionConflict(err error) bool {
	reasons, cancelled := txConditionFailures(err)
	if !cancelled {
		return false
	}
	conflict := false
	for _, r := range reasons {
		if r.Code == nil {
			continue
		}
		switch *r.Code {
		case reasonConditionFailed:
			return false
		case reasonTransactionConflict:
			conflict = true
		}
	}
	return conflict
}

// txConditionFailures maps a cancelled transaction onto its per-item outcomes.
// The returned slice is index-aligned with the TransactWriteItems input, so a
// caller can say which condition lost — the difference between "that email is
// taken" and "that user id is taken" is exactly this.
//
// The second return value is false when the error was not a cancellation, in
// which case it is an ordinary failure and must be reported as such.
func txConditionFailures(err error) ([]types.CancellationReason, bool) {
	var tce *types.TransactionCanceledException
	if !errors.As(err, &tce) {
		return nil, false
	}
	return tce.CancellationReasons, true
}

// txFailedAt reports whether the transaction was cancelled because the condition
// on operation i failed, and returns that item's pre-image if one came back.
func txFailedAt(reasons []types.CancellationReason, i int) (map[string]types.AttributeValue, bool) {
	if i >= len(reasons) {
		return nil, false
	}
	r := reasons[i]
	if r.Code == nil || *r.Code != reasonConditionFailed {
		return nil, false
	}
	return r.Item, true
}
