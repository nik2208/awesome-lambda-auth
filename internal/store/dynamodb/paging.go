package dynamodb

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DynamoDB request-shape limits, from the API reference. They are named here
// because three fan-out operations must page around them (data-model.md §6.4).
const (
	maxBatchWriteItems = 25
	maxBatchGetItems   = 100
)

// unprocessedAttempts bounds the retry loop for a batch that came back partially
// applied. BatchWriteItem reports throttled items rather than failing, so the
// caller — not the SDK's retryer — owns that loop.
const unprocessedAttempts = 8

// queryAll drains a paginated Query. cap is a hard ceiling: the interfaces this
// serves take no cursor, so an unbounded drain would turn one abusive account
// into a Lambda timeout. Exceeding it is ErrResultTooLarge, never a silent
// truncation.
func (s *Store) queryAll(ctx context.Context, in *awsddb.QueryInput, limit int) ([]map[string]types.AttributeValue, error) {
	var out []map[string]types.AttributeValue
	for {
		page, err := s.api.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if len(out) > limit {
			return nil, ErrResultTooLarge
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
}

// deleteKeys removes items in batches, retrying whatever DynamoDB reports as
// unprocessed. The whole fan-out is idempotent: a delete of an absent item
// succeeds, so a partial failure is safe to retry from the top.
func (s *Store) deleteKeys(ctx context.Context, keys []map[string]types.AttributeValue) error {
	for start := 0; start < len(keys); start += maxBatchWriteItems {
		end := min(start+maxBatchWriteItems, len(keys))
		reqs := make([]types.WriteRequest, 0, end-start)
		for _, k := range keys[start:end] {
			reqs = append(reqs, types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: k}})
		}
		pending := map[string][]types.WriteRequest{s.table: reqs}
		for attempt := 0; len(pending) > 0; attempt++ {
			if attempt == unprocessedAttempts {
				return errors.New("dynamodb: batch delete still unprocessed after retries")
			}
			if attempt > 0 {
				if err := sleepCtx(ctx, backoff(attempt)); err != nil {
					return err
				}
			}
			resp, err := s.api.BatchWriteItem(ctx, &awsddb.BatchWriteItemInput{RequestItems: pending})
			if err != nil {
				return err
			}
			pending = resp.UnprocessedItems
		}
	}
	return nil
}

// batchGet fetches items by key from the main table, following UnprocessedKeys.
// It is used where a GSI1 query hands back keys and the caller needs the full
// item: the index projects only three attributes on purpose (§5).
func (s *Store) batchGet(ctx context.Context, keys []map[string]types.AttributeValue) ([]map[string]types.AttributeValue, error) {
	out := make([]map[string]types.AttributeValue, 0, len(keys))
	for start := 0; start < len(keys); start += maxBatchGetItems {
		end := min(start+maxBatchGetItems, len(keys))
		pending := map[string]types.KeysAndAttributes{
			s.table: {Keys: keys[start:end], ConsistentRead: aws.Bool(true)},
		}
		for attempt := 0; len(pending) > 0; attempt++ {
			if attempt == unprocessedAttempts {
				return nil, errors.New("dynamodb: batch get still unprocessed after retries")
			}
			if attempt > 0 {
				if err := sleepCtx(ctx, backoff(attempt)); err != nil {
					return nil, err
				}
			}
			resp, err := s.api.BatchGetItem(ctx, &awsddb.BatchGetItemInput{RequestItems: pending})
			if err != nil {
				return nil, err
			}
			out = append(out, resp.Responses[s.table]...)
			pending = resp.UnprocessedKeys
		}
	}
	return out, nil
}

// backoff is deliberately coarse. Unprocessed items mean the table is shedding
// load, and a Lambda has a deadline, so this trades a few hundred milliseconds
// for a much better chance of finishing rather than optimising the fast path.
func backoff(attempt int) time.Duration {
	d := 25 * time.Millisecond << attempt
	if d > time.Second {
		d = time.Second
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
