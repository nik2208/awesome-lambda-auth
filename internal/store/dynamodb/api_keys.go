package dynamodb

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// This file implements auth.APIKeyStore — the five-method interface core v0.8.0
// completed — and three of its four narrow companions: APIKeyAdminStore,
// APIKeyServiceIndexStore and APIKeyDeleteStore. The fourth, APIKeyAuditStore,
// is deliberately not implemented; interfaces.go says why.
//
// # Two items per key, and why neither is optional
//
//	canonical  PK=APIKEY#<prefix>  SK=APIKEY  GSI1PK=APIKEY             GSI1SK=<descCreatedAt>#<id>
//	pointer    PK=KEYID#<id>       SK=KEYID   GSI1PK=APIKEYSVC#<svc>    GSI1SK=<descCreatedAt>#<id>
//
// APIKeyRecord has no user id and no tenant id — only ServiceID — so it cannot
// live under a user partition (§2.3). Lookup on the hot path is by Prefix
// (FindByPrefix, one GetItem per authenticated request) and every mutation is by
// ID (FindByID, Revoke, UpdateLastUsed, Delete), so two keys are unavoidable:
// the canonical record keyed by prefix, and a pointer keyed by id that carries
// the prefix and nothing else it does not need.
//
// # The two GSI1 roles, and why they are on different items
//
// One item has one GSI1 key pair, and this entity needs two fan-outs: ListAll
// enumerates every key, ListByServiceID enumerates one service identity's. So
// the canonical item carries the all-keys directory and the pointer carries the
// by-service one.
//
// That split is not arbitrary. ListAll is the one the admin screen actually
// calls, and putting it on the canonical item makes it a Query plus one
// BatchGetItem of the records themselves. ListByServiceID is called by nothing
// in the reference — it is declared, described as needed "only if you expose a
// key-listing UI", and reached by no route, strategy or service — so the extra
// hop it pays (index → pointers → prefixes → records) lands on the method that
// has no caller rather than on the one that does.
//
// # No TTL, deliberately, and §2.2 is corrected
//
// The catalogue marked both items "optional" TTL, presumably keyed off
// APIKeyRecord.ExpiresAt. They carry none. FindByID is contractually required to
// return a record "whatever its state — active, revoked or expired", because it
// is "used for revocation, rotation, and admin management" and a management
// screen that could not open an expired key could not show an operator the thing
// that just stopped working. A TTL would delete exactly those records.
//
// # Ordering, reproduced rather than registered
//
// The core's normative order for both listings is CreatedAt **descending**, ties
// broken by ID **ascending** — a total order, and the totality is the
// load-bearing half, since limit/offset paging over a partial order repeats some
// rows and drops others. A sort key of `<createdAt>#<id>` read backwards would
// give ID descending on the tie, which is a different order; so the key holds
// descendingStamp(CreatedAt) instead, whose ascending byte order is descending
// time, and an ordinary forward Query answers exactly the contract. Records with
// a zero CreatedAt sort last, as the core requires, because descendingStamp maps
// a zero instant to the earliest one.

// API key attributes (data-model.md §5). `name`, `isActive`, `expiresAt`,
// `createdAt` and `updatedAt` are declared elsewhere and shared: one attribute
// name is one constant in this package.
const (
	attrKeyID      = "keyId"
	attrPrefix     = "prefix"
	attrServiceID  = "serviceId"
	attrKeyHash    = "keyHash"
	attrScopes     = "scopes"
	attrAllowedIPs = "allowedIPs"
	attrLastUsedAt = "lastUsedAt"
)

// maxAPIKeysPerService bounds ListByServiceID, whose interface declares no limit
// and no offset — "the whole set comes back", as it does in the reference, "so a
// service identity with a pathological number of keys is the caller's problem".
// It is the caller's problem there and a Lambda timeout here, so it is capped
// and refuses rather than truncating, exactly as ListForUser does.
const maxAPIKeysPerService = 1000

// apiKeyLastUsedThrottle is the minimum interval between two lastUsedAt writes
// for one key.
//
// UpdateLastUsed fires on *every* API-key-authenticated request (the core's
// Verify calls it and discards the error), so unthrottled it is one write per
// request against a single item — the worst write shape DynamoDB has, since
// adaptive capacity cannot split one item. §6.3 asked for one write per key per
// 60 s and this is it, expressed as a condition rather than as a cache so that
// it holds across execution environments.
//
// The resulting timestamp is up to a minute stale. No consumer of LastUsedAt
// cares: it is rendered on an admin screen and the reference's own strategy
// writes it best-effort.
const apiKeyLastUsedThrottle = time.Minute

// ErrAPIKeyExists means Save lost its uniqueness condition: either the id or,
// far more interestingly, the prefix was already taken.
//
// The prefix case is the one worth a typed error. The prefix is `ak_` plus 8 hex
// characters — 32 bits — so a birthday collision is expected at around 77 000
// live keys (§2.3), and the canonical item is keyed by it. Without the
// condition, a collision would silently overwrite a live key and turn every
// authentication with it into a failure nobody could explain. With it, the
// collision is a loud Save error the caller can retry into a fresh key. The core
// does not retry today; §8.9 has it open as an upstream question.
var ErrAPIKeyExists = errors.New("dynamodb: api key prefix or id already exists")

// APIKeys returns this store as the auth.APIKeyStore the composition root hands
// to auth.APIKeyMiddleware and auth.APIKeyService. The methods are on *Store
// itself; the accessor exists so cmd/auth can find the capability structurally.
func (s *Store) APIKeys() auth.APIKeyStore { return s }

// The five-method interface and the three companions this store implements.
//
// The companions are the reason the core split them one to an interface rather
// than gathering them into one admin interface: the admin routes distinguish the
// absences one at a time and answer differently for each — a 501 naming the
// single missing method for listAll, and a 200 with a note saying the key was
// revoked instead for a missing delete. All three are reached by type assertion,
// so a drift in any of them is a route changing its answer rather than a build
// failing. APIKeyAuditStore is absent on purpose; see interfaces.go.
var (
	_ auth.APIKeyStore             = (*Store)(nil)
	_ auth.APIKeyAdminStore        = (*Store)(nil)
	_ auth.APIKeyServiceIndexStore = (*Store)(nil)
	_ auth.APIKeyDeleteStore       = (*Store)(nil)
)

// Save persists a newly minted record, refusing to overwrite either key.
//
// A transaction, because the two items have to appear together: a canonical
// record with no pointer is a key that authenticates and cannot be revoked, and
// a pointer with no record is a row four methods resolve to nothing.
//
// Both writes are conditional on absence. The reference's own example is a bare
// insert with no collision rule and none imposed — but the reference is not
// keyed by prefix, and this store is; see ErrAPIKeyExists.
func (s *Store) Save(ctx context.Context, k auth.APIKeyRecord) error {
	if err := checkID("api key id", k.ID); err != nil {
		return err
	}
	if err := checkOpaque("api key prefix", k.Prefix, maxAPIKeyPrefixLen); err != nil {
		return err
	}
	if err := checkServiceID(k.ServiceID); err != nil {
		return err
	}

	notExists := "attribute_not_exists(#PK)"
	names := exprNames(attrPK)
	err := s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName:                aws.String(s.table),
				Item:                     s.apiKeyItem(k),
				ConditionExpression:      aws.String(notExists),
				ExpressionAttributeNames: names,
			}},
			{Put: &types.Put{
				TableName:                aws.String(s.table),
				Item:                     s.apiKeyPointerItem(k),
				ConditionExpression:      aws.String(notExists),
				ExpressionAttributeNames: names,
			}},
		},
	})
	if err != nil {
		if reasons, ok := txConditionFailures(err); ok {
			// Either condition losing means the same thing to the caller — mint
			// another key — so no distinction is invented, exactly as CreateUser
			// answers one ErrUserExists for a taken id and a taken address.
			if _, failed := txFailedAt(reasons, 0); failed {
				return ErrAPIKeyExists
			}
			if _, failed := txFailedAt(reasons, 1); failed {
				return ErrAPIKeyExists
			}
		}
		return wrap("save api key", err)
	}
	return nil
}

// FindByPrefix returns the *active* record for a prefix, and nothing else.
//
// The filter is the contract — "Only return records where isActive = true" — and
// honouring it changes no behaviour, because the core's Verify re-checks
// IsActive on whatever comes back. Not honouring it would: a revoked key would
// start authenticating the moment anything stopped re-checking. The revoked
// record stays reachable for the admin screens through FindByID, which is the
// deliberate opposite of this method.
//
// Expiry is *not* filtered here. The contract names IsActive and nothing else,
// Verify checks ExpiresAt itself, and a store that also dropped expired keys
// would be making a second policy decision the interface did not ask for.
//
// One strongly-consistent GetItem: this is the hot path, and a stale read is a
// failed authentication for a key that was just minted.
func (s *Store) FindByPrefix(ctx context.Context, prefix string) (auth.APIKeyRecord, error) {
	if err := checkOpaque("api key prefix", prefix, maxAPIKeyPrefixLen); err != nil {
		// A prefix the store cannot key is a prefix it does not hold. Verify
		// collapses this into ErrInvalidCredentials either way.
		return auth.APIKeyRecord{}, auth.ErrAPIKeyNotFound
	}
	m, err := s.apiKeyItemByPrefix(ctx, prefix)
	if err != nil || m == nil {
		if m == nil && err == nil {
			return auth.APIKeyRecord{}, auth.ErrAPIKeyNotFound
		}
		return auth.APIKeyRecord{}, err
	}
	rec, err := apiKeyFromItem(m)
	if err != nil {
		return auth.APIKeyRecord{}, err
	}
	if !rec.IsActive {
		return auth.APIKeyRecord{}, auth.ErrAPIKeyNotFound
	}
	return rec, nil
}

// FindByID returns the record with this id whatever its state — active, revoked
// or expired.
//
// Two reads, and they are the price of the split key space: the pointer resolves
// the id to a prefix, and the prefix addresses the record. Nothing on the
// authentication path calls this, so the extra round trip lands where it costs
// nothing.
func (s *Store) FindByID(ctx context.Context, id string) (auth.APIKeyRecord, error) {
	prefix, err := s.apiKeyPrefixForID(ctx, id)
	if err != nil {
		return auth.APIKeyRecord{}, err
	}
	m, err := s.apiKeyItemByPrefix(ctx, prefix)
	if err != nil {
		return auth.APIKeyRecord{}, err
	}
	if m == nil {
		// A pointer whose record has gone. Nothing here produces that state —
		// Delete removes both in one transaction — so it means an operator
		// removed one item by hand; answering "not found" is the honest report.
		return auth.APIKeyRecord{}, auth.ErrAPIKeyNotFound
	}
	return apiKeyFromItem(m)
}

// Revoke marks the key inactive. A soft delete, which is the one the reference
// prefers — "prefer revoke for audit-trail preservation" — so the record stays
// readable through FindByID afterwards.
//
// An id that matches nothing is not an error, and neither is a record that has
// gone: the reference's example is an unconditional update behind a where({id}),
// which no-ops on a miss, and the admin route awaits it and answers
// 200 {"success": true} with no lookup of its own. A store that answered
// ErrAPIKeyNotFound here would turn that 200 into a 500.
func (s *Store) Revoke(ctx context.Context, id string) error {
	prefix, err := s.apiKeyPrefixForID(ctx, id)
	if errors.Is(err, auth.ErrAPIKeyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                aws.String(s.table),
		Key:                      key(apiKeyPK(prefix), skAPIKey),
		UpdateExpression:         aws.String("SET #isActive = :off, #updatedAt = :now"),
		ConditionExpression:      aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames: exprNames(attrPK, attrIsActive, attrUpdatedAt),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":off": &types.AttributeValueMemberBOOL{Value: false},
			":now": avS(formatTime(s.nowUTC())),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return nil
		}
		return wrap("revoke api key", err)
	}
	return nil
}

// UpdateLastUsed stamps the record after a successful authentication, at most
// once per apiKeyLastUsedThrottle.
//
// The throttle is a ConditionExpression rather than a cache, so it holds across
// execution environments: `attribute_not_exists(lastUsedAt) OR lastUsedAt <
// :staleBefore`. The lexicographic comparison is a chronological one only
// because tsLayout pads to a fixed width — the same equivalence the single-use
// token conditions rely on.
//
// A lost condition is success, not an error: it means another request stamped
// the key moments ago, which is the outcome this method wanted. The core's
// Verify discards this error in any case, so a store may treat the whole method
// as best-effort; treating the *throttle* as an error would still be wrong,
// because it would make an untraceable failure out of the normal path.
func (s *Store) UpdateLastUsed(ctx context.Context, id string, when time.Time) error {
	prefix, err := s.apiKeyPrefixForID(ctx, id)
	if errors.Is(err, auth.ErrAPIKeyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:        aws.String(s.table),
		Key:              key(apiKeyPK(prefix), skAPIKey),
		UpdateExpression: aws.String("SET #lastUsedAt = :when"),
		ConditionExpression: aws.String(
			"attribute_exists(#PK) AND (attribute_not_exists(#lastUsedAt) OR #lastUsedAt < :staleBefore)"),
		ExpressionAttributeNames: exprNames(attrPK, attrLastUsedAt),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":when":        avS(formatTime(when.UTC())),
			":staleBefore": avS(formatTime(when.UTC().Add(-apiKeyLastUsedThrottle))),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return nil
		}
		return wrap("update api key last used", err)
	}
	return nil
}

// Delete is APIKeyDeleteStore: a hard delete, audit trail and all.
//
// The reference's own advice is not to implement it, and DELETE
// /admin/api/api-keys/:id is written so that declining costs nothing — it
// revokes instead and says so in the body. It is implemented anyway because the
// route can only make that choice if the *absence of this one method* is
// observable, and a deployment that wants the hard delete should not have to
// fork the store to get it; which of the two the operator gets is the admin
// surface's decision, not this package's.
//
// The canonical delete is conditional on ownership — `keyId = :id` — for
// LinkedAccounts.Delete's reason: unconditional, a Delete arriving after a
// prefix collision had been resolved into a different key would remove the live
// record. When that condition loses, the pointer alone is dropped and the call
// still reports success, which is what the route expects.
//
// An id that matches nothing is a no-op returning nil, as it is on Revoke.
func (s *Store) Delete(ctx context.Context, id string) error {
	prefix, err := s.apiKeyPrefixForID(ctx, id)
	if errors.Is(err, auth.ErrAPIKeyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	pointerKey := key(keyIDPK(id), skKeyID)
	err = s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{
				TableName:                 aws.String(s.table),
				Key:                       key(apiKeyPK(prefix), skAPIKey),
				ConditionExpression:       aws.String("attribute_not_exists(#PK) OR #keyId = :id"),
				ExpressionAttributeNames:  exprNames(attrPK, attrKeyID),
				ExpressionAttributeValues: map[string]types.AttributeValue{":id": avS(id)},
			}},
			{Delete: &types.Delete{TableName: aws.String(s.table), Key: pointerKey}},
		},
	})
	if err != nil {
		if reasons, ok := txConditionFailures(err); ok {
			if _, failed := txFailedAt(reasons, 0); failed {
				// The prefix now belongs to somebody else. Drop our pointer and
				// report success: the record this id named is gone either way.
				return s.deleteKeys(ctx, []map[string]types.AttributeValue{pointerKey})
			}
		}
		return wrap("delete api key", err)
	}
	return nil
}

// ListAll is APIKeyAdminStore: one page of every key, newest first.
//
// The canonical items are themselves the directory, so an index entry names its
// own record and one BatchGetItem finishes the page.
func (s *Store) ListAll(ctx context.Context, limit, offset int) ([]auth.APIKeyRecord, error) {
	items, err := s.pagedIndexQuery(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		IndexName:                aws.String(s.index),
		KeyConditionExpression:   aws.String("#GSI1PK = :pk"),
		ExpressionAttributeNames: exprNames(attrGSI1PK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(gsi1AllAPIKeysPK),
		},
	}, limit, offset, canonicalKeyOfEntry)
	if err != nil {
		if errors.Is(err, ErrPageWindowTooLarge) {
			return nil, err
		}
		return nil, wrap("list api keys", err)
	}
	return apiKeysFromItems(items)
}

// ListByServiceID is APIKeyServiceIndexStore: every key issued to one service
// identity, active or not, newest first.
//
// Three hops rather than two, because the by-service index is on the pointer
// item — see the file header for why it is there and not on the record. The
// whole set comes back, capped at maxAPIKeysPerService and refusing rather than
// truncating.
func (s *Store) ListByServiceID(ctx context.Context, serviceID string) ([]auth.APIKeyRecord, error) {
	if err := checkServiceID(serviceID); err != nil {
		return nil, err
	}
	entries, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		IndexName:                aws.String(s.index),
		KeyConditionExpression:   aws.String("#GSI1PK = :svc"),
		ExpressionAttributeNames: exprNames(attrGSI1PK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":svc": avS(gsi1APIKeyService(serviceID)),
		},
	}, maxAPIKeysPerService)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap("query api keys by service", err)
	}
	if len(entries) == 0 {
		return []auth.APIKeyRecord{}, nil
	}

	// Hop one: the pointers, in index order, for their prefixes.
	pointers, err := s.resolveIndexEntries(ctx, entries, canonicalKeyOfEntry)
	if err != nil {
		return nil, wrap("resolve api key pointers", err)
	}
	// Hop two: the records those prefixes name, put back into the same order.
	keys := make([]map[string]types.AttributeValue, 0, len(pointers))
	for _, p := range pointers {
		if prefix := getS(p, attrPrefix); prefix != "" {
			keys = append(keys, key(apiKeyPK(prefix), skAPIKey))
		}
	}
	records, err := s.batchGet(ctx, keys)
	if err != nil {
		return nil, wrap("list api keys by service", err)
	}
	byKey := make(map[string]map[string]types.AttributeValue, len(records))
	for _, m := range records {
		byKey[keyString(getS(m, attrPK), getS(m, attrSK))] = m
	}
	ordered := make([]map[string]types.AttributeValue, 0, len(keys))
	for _, k := range keys {
		if m, ok := byKey[keyString(getS(k, attrPK), getS(k, attrSK))]; ok {
			ordered = append(ordered, m)
		}
	}
	return apiKeysFromItems(ordered)
}

// apiKeyItemByPrefix reads the canonical record. nil means absent.
func (s *Store) apiKeyItemByPrefix(ctx context.Context, prefix string) (map[string]types.AttributeValue, error) {
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(apiKeyPK(prefix), skAPIKey),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, wrap("get api key", err)
	}
	if len(out.Item) == 0 {
		return nil, nil
	}
	return out.Item, nil
}

// apiKeyPrefixForID resolves the by-id pointer. ErrAPIKeyNotFound for an id the
// store does not hold, including one it could never have keyed.
func (s *Store) apiKeyPrefixForID(ctx context.Context, id string) (string, error) {
	if err := checkID("api key id", id); err != nil {
		return "", auth.ErrAPIKeyNotFound
	}
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(keyIDPK(id), skKeyID),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return "", wrap("get api key pointer", err)
	}
	if len(out.Item) == 0 {
		return "", auth.ErrAPIKeyNotFound
	}
	if err := checkVersion(out.Item, typeAPIKeyID); err != nil {
		return "", err
	}
	prefix := getS(out.Item, attrPrefix)
	if prefix == "" {
		return "", auth.ErrAPIKeyNotFound
	}
	return prefix, nil
}

// apiKeyItem encodes the canonical record (data-model.md §5, "API key").
//
// isActive is written even when false, because a flag whose absence was
// indistinguishable from "revoked" would make FindByPrefix's filter unreadable.
// createdAt likewise: the core declares it non-optional, a zero value means a
// record that predates the field or a store that lost it, and both are worth
// being able to see.
func (s *Store) apiKeyItem(k auth.APIKeyRecord) item {
	return item{}.
		sAlways(attrPK, apiKeyPK(k.Prefix)).
		sAlways(attrSK, skAPIKey).
		stamp(typeAPIKey).
		sAlways(attrKeyID, k.ID).
		sAlways(attrPrefix, k.Prefix).
		s(attrName, k.Name).
		s(attrServiceID, k.ServiceID).
		sAlways(attrKeyHash, k.KeyHash).
		// Written only when non-nil, so nil round-trips as nil. An L of S rather
		// than an SS for stringListAV's reasons — DynamoDB forbids an empty SS,
		// and a set would silently reorder and deduplicate a list the admin
		// listing renders. §5 said SS; it is corrected.
		avIf(attrScopes, k.Scopes != nil, func() types.AttributeValue { return stringListAV(k.Scopes) }).
		avIf(attrAllowedIPs, k.AllowedIPs != nil, func() types.AttributeValue { return stringListAV(k.AllowedIPs) }).
		b(attrIsActive, k.IsActive).
		tp(attrExpiresAt, k.ExpiresAt).
		tp(attrLastUsedAt, k.LastUsedAt).
		sAlways(attrCreatedAt, formatTime(k.CreatedAt)).
		sAlways(attrGSI1PK, gsi1AllAPIKeysPK).
		sAlways(attrGSI1SK, apiKeyDirectorySK(k))
}

// apiKeyPointerItem is the by-id pointer. Deliberately minimal — it exists so
// four methods can name the canonical key, and it carries the by-service index
// because the canonical item's GSI1 pair is already spent.
//
// keyHash is not on it, and that is not an oversight: the hash is the credential,
// and §5's rule is that a secret exists in exactly one place.
func (s *Store) apiKeyPointerItem(k auth.APIKeyRecord) item {
	return item{}.
		sAlways(attrPK, keyIDPK(k.ID)).
		sAlways(attrSK, skKeyID).
		stamp(typeAPIKeyID).
		sAlways(attrKeyID, k.ID).
		sAlways(attrPrefix, k.Prefix).
		s(attrServiceID, k.ServiceID).
		sAlways(attrCreatedAt, formatTime(k.CreatedAt)).
		sAlways(attrGSI1PK, gsi1APIKeyService(k.ServiceID)).
		sAlways(attrGSI1SK, apiKeyDirectorySK(k))
}

// apiKeyDirectorySK is the sort key both indexes use: the complement of the
// creation instant, then the id. Ascending byte order is therefore CreatedAt
// descending and ID ascending, which is the core's normative order exactly. See
// descendingStamp.
func apiKeyDirectorySK(k auth.APIKeyRecord) string {
	return descendingStamp(k.CreatedAt) + keySep + k.ID
}

func apiKeyFromItem(m map[string]types.AttributeValue) (auth.APIKeyRecord, error) {
	if err := checkVersion(m, typeAPIKey); err != nil {
		return auth.APIKeyRecord{}, err
	}
	rec := auth.APIKeyRecord{
		ID:         getS(m, attrKeyID),
		Prefix:     getS(m, attrPrefix),
		Name:       getS(m, attrName),
		ServiceID:  getS(m, attrServiceID),
		KeyHash:    getS(m, attrKeyHash),
		Scopes:     stringListFromAV(m[attrScopes]),
		AllowedIPs: stringListFromAV(m[attrAllowedIPs]),
		IsActive:   getBool(m, attrIsActive),
	}
	var err error
	if rec.ExpiresAt, err = getTimePtr(m, attrExpiresAt); err != nil {
		return auth.APIKeyRecord{}, err
	}
	if rec.LastUsedAt, err = getTimePtr(m, attrLastUsedAt); err != nil {
		return auth.APIKeyRecord{}, err
	}
	if rec.CreatedAt, err = getTime(m, attrCreatedAt); err != nil {
		return auth.APIKeyRecord{}, err
	}
	return rec, nil
}

func apiKeysFromItems(items []map[string]types.AttributeValue) ([]auth.APIKeyRecord, error) {
	out := make([]auth.APIKeyRecord, 0, len(items))
	for _, m := range items {
		rec, err := apiKeyFromItem(m)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}
