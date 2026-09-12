package dynamodb

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// This file implements auth.UserMetadataStore (data-model.md §1.4 #26-#28): the
// arbitrary key/value bag hung off a user, read by /me and written by the admin
// metadata route.
//
// # One item per key
//
// PK=USERMETA#<u>, SK=META#<key>, one item per entry. §2.3 argues it and the
// argument is UpdateMetadata's: the reference *merges*, it does not replace
// (feature_stores.go writes each key over whatever is there and leaves the rest
// alone), and per-key items make that a write with no read. The alternative —
// one item holding a nested map — cannot be merged in a single call: `SET #d.#k
// = :v` fails when `#d` does not exist, and initialising it in the same
// expression is a conflicting-path error, so it degrades to a read-modify-write
// and two concurrent merges of different keys lose one.
//
// The cost §2.3 accepted is here as stated: GetMetadata is a Query and
// ClearMetadata a Query plus a BatchWrite, which is **not** atomic. A partial
// failure during DELETE /account orphans metadata under a deleted user. The
// mitigation is that the delete is driven off the same query and is idempotent
// on retry, and that DeleteUser sweeps the partition too — so the orphan needs
// both calls to fail.
//
// # The partition is not the user's item collection, and it could not be
//
// §1.4 put these items under USER#<t>#<u>. That is impossible to address:
// UserMetadataStore's three methods take (ctx, userID) and carry no tenant, so
// nothing can name the `<t>` segment. §8.1 logged this as an open question whose
// interim was "read the tenant off the request-scoped principal" and whose fix
// was an upstream signature widening.
//
// Neither is needed, because the table already answers this question once. The
// linked-account item is keyed globally and carries no tenantId — "deliberately
// absent" (§5) — for exactly the reason that FindByProvider, ListForUser and
// Delete carry no tenant either. Metadata follows it. A user id is unique across
// tenants by construction (32 hex characters of randomness behind a `usr_`
// prefix), so a partition keyed on it alone is exactly as isolating as one keyed
// on both, and §3's rule — isolation is a property of the key, never of a filter
// — is satisfied rather than bent: there is no filter, and no query written
// against this key space can reach a user the caller did not name.
//
// §8.1 is closed by this rather than deferred, and §1.4 and §2.2 are corrected.
// The one consequence to keep in view is that the /me bundle is now two Queries
// rather than one, which §2.2's item-collection discipline paragraph records.

// attrMetaValue holds the entry's value, of whatever DynamoDB type anyAV
// produced. The key is the tail of SK and is not duplicated into an attribute,
// as a mail template's id is not.
const attrMetaValue = "value"

// MaxMetadataValueBytes caps one entry as itemBytes accounts for it.
//
// Lower than the 300 KB the template and settings documents get, and
// deliberately so: those are one item per deployment, where this is one item per
// key per user and the aggregate GetMetadata returns is the product. 64 KB is
// the figure §6.3 named for the aggregate; applied per entry, together with
// Options.MaxMetadataKeysPerUser on the count, it bounds that aggregate without
// making every write read the whole set first.
const MaxMetadataValueBytes = 64 * 1024

// ErrMetadataTooLarge means one metadata entry exceeds MaxMetadataValueBytes.
// Nothing was written — the whole UpdateMetadata call is refused before its
// first batch, so a caller never has to work out which half of a merge landed.
var ErrMetadataTooLarge = errors.New("dynamodb: metadata entry exceeds the item size limit")

// Metadata returns this store as the auth.UserMetadataStore the composition root
// hands to auth.WithMetadataProvider. The methods are on *Store itself; the
// accessor exists so cmd/auth can find the capability structurally.
func (s *Store) Metadata() auth.UserMetadataStore { return s }

// UserMetadataStore is handed to the core by name (auth.WithMetadataProvider),
// so a drifted signature fails the composition root's build. See interfaces.go
// for the convention.
var _ auth.UserMetadataStore = (*Store)(nil)

// GetMetadata reads every entry for a user.
//
// Strongly consistent: the admin route that writes a key renders the result
// immediately afterwards, and an eventually-consistent read would make that a
// race the operator sees as a lost edit.
//
// A user with no metadata answers an empty map and no error, never nil, which is
// what MemoryMetadataStore does — it allocates and ranges over a nil map — and
// what keeps the value encoding as `{}` on the wire rather than as `null`.
func (s *Store) GetMetadata(ctx context.Context, userID string) (map[string]any, error) {
	if err := checkID("user id", userID); err != nil {
		return nil, err
	}
	items, err := s.metadataItems(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(items))
	for _, m := range items {
		if err := checkVersion(m, typeMeta); err != nil {
			return nil, err
		}
		k, ok := metaKeyFromSK(getS(m, attrSK))
		if !ok {
			continue
		}
		out[k] = anyFromAV(m[attrMetaValue])
	}
	return out, nil
}

// UpdateMetadata merges: a key the argument carries replaces the stored entry,
// a key it does not carry is left alone. That is MemoryMetadataStore's semantics
// exactly, and it is why the items are per key.
//
// # Why the whole call is validated before the first write
//
// A BatchWriteItem cannot be a transaction, so a merge of twenty keys is not
// atomic and a failure halfway leaves half of them written. That is unavoidable
// — TransactWriteItems caps at 100 items and costs 2× WCU, and the reference's
// own merge is not atomic either — but a failure caused by input this store
// could have rejected up front is avoidable, so every value is encoded and
// measured before anything is written. What remains non-atomic is a genuine
// infrastructure failure, and a retry of the same call is idempotent.
//
// An empty map is a no-op and not an error, matching the memory store's empty
// range.
func (s *Store) UpdateMetadata(ctx context.Context, userID string, metadata map[string]any) error {
	if err := checkID("user id", userID); err != nil {
		return err
	}
	if len(metadata) == 0 {
		return nil
	}

	reqs := make([]types.WriteRequest, 0, len(metadata))
	for k, v := range metadata {
		if err := checkOpaque("metadata key", k, maxMetaKeyLen); err != nil {
			return err
		}
		av, err := anyAV(v)
		if err != nil {
			return fmt.Errorf("metadata key %q: %w", k, err)
		}
		it := s.metadataItem(userID, k, av)
		if n := itemBytes(it); n > MaxMetadataValueBytes {
			return wrapSize(ErrMetadataTooLarge, k, n, MaxMetadataValueBytes)
		}
		reqs = append(reqs, types.WriteRequest{PutRequest: &types.PutRequest{Item: it}})
	}
	if err := s.batchWrite(ctx, reqs); err != nil {
		return wrap("update metadata", err)
	}
	return nil
}

// ClearMetadata removes every entry for a user.
//
// Query then BatchWrite, and not atomic — see the file header. A user with no
// metadata is a no-op, matching the memory store's unconditional map delete.
func (s *Store) ClearMetadata(ctx context.Context, userID string) error {
	if err := checkID("user id", userID); err != nil {
		return err
	}
	keys, err := s.metadataKeys(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.deleteKeys(ctx, keys); err != nil {
		return wrap("clear metadata", err)
	}
	return nil
}

// metadataItems drains one user's metadata partition, capped.
func (s *Store) metadataItems(ctx context.Context, userID string) ([]map[string]types.AttributeValue, error) {
	items, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		KeyConditionExpression:   aws.String("#PK = :pk AND begins_with(#SK, :prefix)"),
		ExpressionAttributeNames: exprNames(attrPK, attrSK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":     avS(userMetaPK(userID)),
			":prefix": avS(skMetaPrefix),
		},
		ConsistentRead: aws.Bool(true),
	}, s.maxMetadataKeys)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap("query metadata", err)
	}
	return items, nil
}

// metadataKeys is metadataItems reduced to main-table keys. It is what
// ClearMetadata deletes and what DeleteUser adds to its own sweep, so the two
// cannot disagree about which items belong to a user.
func (s *Store) metadataKeys(ctx context.Context, userID string) ([]map[string]types.AttributeValue, error) {
	items, err := s.metadataItems(ctx, userID)
	if err != nil {
		return nil, err
	}
	keys := make([]map[string]types.AttributeValue, 0, len(items))
	for _, m := range items {
		keys = append(keys, key(getS(m, attrPK), getS(m, attrSK)))
	}
	return keys, nil
}

func (s *Store) metadataItem(userID, k string, value types.AttributeValue) item {
	return item{}.
		sAlways(attrPK, userMetaPK(userID)).
		sAlways(attrSK, metaSK(k)).
		stamp(typeMeta).
		sAlways(attrUserID, userID).
		av(attrMetaValue, value).
		sAlways(attrUpdatedAt, formatTime(s.nowUTC()))
}
