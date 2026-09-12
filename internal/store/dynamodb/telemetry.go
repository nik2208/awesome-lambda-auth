package dynamodb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// This file implements auth.TelemetryStore (data-model.md §1.5 #59-#60): the
// per-event log POST /tools/track/:eventName writes and GET /tools/telemetry
// reads. Neither route is mounted here — the tools router is P7 — so this is a
// seam, and the seam is what a deployment's dashboards will be built against.
//
//	PK=TEL#<tenantID>#<yyyy-mm-dd>   SK=<rfc3339Nano>#<eventId>   ttl
//
// Day buckets inside a tenant partition. §8.11 called that partitioning "a
// guess" and asked for a review; this is the review, and the key survives it
// with three corrections to what the rows around it assumed.
//
// # The time range is not optional, and the store supplies it when the caller
// does not
//
// TelemetryFilter's zero value has no Since and no Until, and
// MemoryTelemetryStore answers it by walking everything it holds. A day-bucketed
// store cannot: "everything" is an unbounded set of partitions and there is no
// index that enumerates which of them exist. So a filter with no Since starts at
// the retention horizon — now minus Options.TelemetryRetention, which is also
// the TTL every event is written with — and one with no Until ends at now.
//
// Those two defaults are chosen so the two meanings agree: the horizon is
// exactly the point before which the store holds nothing, so "no time range"
// returns everything still stored, which is what the memory store's answer means
// too. A deployment that lengthens the retention lengthens both together,
// because they are one number.
//
// # The tenant is a literal, not a wildcard, and that is a registered deviation
//
// TelemetryFilter.TenantID empty means "no filter" to MemoryTelemetryStore. Here
// it is an ordinary tenant value naming its own partition — the rule everywhere
// else in this package, and the only one a key-partitioned store can offer
// without a cross-partition Scan.
//
// In a single-tenant deployment the difference is unobservable: every event
// carries the same empty tenant, so filtering on it and not filtering at all
// return the same set. In a multi-tenant one the store refuses outright
// (checkTenant answers ErrTenantRequired), which is better than silently
// answering for one tenant a caller meant as "all". CompatibilityNotes carries
// it.
//
// This is the one place the treatment differs from AdminUserStore.ListUsers,
// where an empty tenant *is* a wildcard. The difference is the core's: ListUsers
// documents the wildcard explicitly because the reference's own signature has no
// tenant at all, and the profile index is built to answer it. Nothing documents a
// wildcard here, and no index answers it.
//
// # UserID and EventName are FilterExpressions, and that is not a §3 violation
//
// §3 forbids a FilterExpression for *tenant* isolation. These two are not
// isolation, they are the caller's own predicate over a partition the key has
// already scoped, and pushing them into DynamoDB means the rows that do not
// match never cross the wire. §8.11's warning stands and is worth restating: a
// query filtered by UserID reads the whole of each day's partition and discards
// most of it, so a user-scoped telemetry query is expensive. If that becomes a
// real access pattern it wants its own index; it is not one today, because
// nothing calls this method.

// Telemetry attributes. `userId`, `tenantId` and `createdAt` are declared
// elsewhere and shared.
const (
	attrEventID   = "eventId"
	attrEventName = "eventName"
	attrIP        = "ip"
	attrUserAgent = "userAgent"
	attrSuccess   = "success"
	attrError     = "error"
	attrMeta      = "meta"
)

// maxTelemetryDays bounds how many day partitions one Query may visit.
//
// A year plus one. It is reached only by a caller asking for a range longer than
// the default retention, which would be asking for partitions the TTL has
// already emptied; refusing is cheaper than issuing 3 650 Queries to find
// nothing. It is deliberately not the retention itself, so that lengthening the
// retention does not silently become the thing that fails.
const maxTelemetryDays = 366

// maxTelemetryResults bounds a Query whose filter names no Limit.
// MemoryTelemetryStore returns everything when Limit is zero, and a store that
// did the same here would drain a busy tenant's month into a Lambda. It refuses
// rather than truncating, as every other cursorless list in this package does.
const maxTelemetryResults = 10000

// MaxTelemetryBytes caps one event as itemBytes accounts for it.
// TelemetryEvent.Meta is a caller-supplied map with no bound in the interface,
// and this is the one item type in the table written on an unauthenticated
// request path, so an oversize event is a refusal and not a 500 from inside the
// SDK.
const MaxTelemetryBytes = 300 * 1024

// ErrTelemetryTooLarge means one event exceeds MaxTelemetryBytes. Nothing was
// written.
var ErrTelemetryTooLarge = errors.New("dynamodb: telemetry event exceeds the item size limit")

// ErrTelemetryRangeTooLarge means a Query's time range spans more than
// maxTelemetryDays day partitions. Nothing was read.
var ErrTelemetryRangeTooLarge = errors.New("dynamodb: telemetry time range spans too many days")

// Telemetry returns this store as the auth.TelemetryStore the composition root
// will hand to the tools router. The methods are on *Store itself; the accessor
// exists so cmd/auth can find the capability structurally.
func (s *Store) Telemetry() auth.TelemetryStore { return s }

// TelemetryStore is reached by type assertion, so a drift is the telemetry
// routes answering 501 from a binary that built. See interfaces.go for the
// convention.
var _ auth.TelemetryStore = (*Store)(nil)

// Record writes one event.
//
// The id is the caller's when it has one and minted here when it does not.
// MemoryTelemetryStore appends whatever it is handed and never looks at the id,
// so an empty one is a shape the core can produce; here the id is half the sort
// key, and two events recorded in the same nanosecond with no id would be one
// event.
//
// The timestamp likewise: a zero one would bucket the event into 0001-01-01 and
// make it unreachable through any realistic range, so it is stamped from the
// store's clock. Both substitutions are visible in the record the caller can
// read back.
func (s *Store) Record(ctx context.Context, event auth.TelemetryEvent) error {
	if err := s.checkTenant(event.TenantID); err != nil {
		return err
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = s.nowUTC()
	}
	if event.ID == "" {
		id, err := newTelemetryID()
		if err != nil {
			return err
		}
		event.ID = id
	}
	if err := checkOpaque("telemetry event id", event.ID, maxRoleNameLen); err != nil {
		return err
	}

	it, err := s.telemetryItem(event)
	if err != nil {
		return err
	}
	if n := itemBytes(it); n > MaxTelemetryBytes {
		return wrapSize(ErrTelemetryTooLarge, event.ID, n, MaxTelemetryBytes)
	}
	if _, err := s.api.PutItem(ctx, &awsddb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      it,
	}); err != nil {
		return wrap("record telemetry", err)
	}
	return nil
}

// Query answers a filter by visiting one day partition per day of the range,
// oldest first.
//
// That fan-out is the cost of the key, and it is worth stating in numbers: a
// filter that names no Since spans the whole retention, which at the default of
// ninety days is ninety Queries — most of them against partitions that hold
// nothing. A filter that names a range pays one Query per day of it. So the
// cheap call is the one an analytics screen actually makes ("the last day",
// "this week") and the expensive one is the unbounded sweep, which is the right
// way round; if it ever needs to be cheaper, the answer is a coarser bucket for
// cold data rather than an index, because there is nothing here to index on.
//
// Order. MemoryTelemetryStore answers in insertion order, which for a log is
// chronological; this answers chronologically too, because the sort key leads
// with the padded timestamp and the days are visited in order. So the two agree
// without either being told to, and there is nothing to register — the one thing
// that differs is the tenant reading, which is the file header's.
//
// Limit is honoured as the memory store honours it: the walk stops as soon as it
// has that many, so a Limit smaller than a day's events costs one Query. A
// filter with no Limit is capped at maxTelemetryResults and refuses rather than
// truncating.
func (s *Store) Query(ctx context.Context, f auth.TelemetryFilter) ([]auth.TelemetryEvent, error) {
	if err := s.checkTenant(f.TenantID); err != nil {
		return nil, err
	}
	since, until, any, err := s.telemetryRange(f)
	if err != nil {
		return nil, err
	}
	if !any {
		return []auth.TelemetryEvent{}, nil
	}
	limit := f.Limit
	if limit <= 0 {
		limit = maxTelemetryResults
	}

	out := make([]auth.TelemetryEvent, 0, min(limit, 64))
	for day := since.Truncate(24 * time.Hour); !day.After(until); day = day.Add(24 * time.Hour) {
		in := &awsddb.QueryInput{
			TableName:                aws.String(s.table),
			KeyConditionExpression:   aws.String("#PK = :pk AND #SK BETWEEN :from AND :to"),
			ExpressionAttributeNames: exprNames(attrPK, attrSK),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": avS(telemetryPK(f.TenantID, day)),
				// The sort key is <paddedTimestamp>#<eventId>, and the timestamp
				// is fixed-width, so a bound built from the instant alone
				// brackets every id at that instant. The low bound needs nothing
				// appended — "<ts>" sorts before "<ts>#…" — while the high bound
				// appends the byte after the separator, which is above every
				// "<ts>#…" key and below every later timestamp. Appending a
				// maximal *character* instead would depend on what bytes an event
				// id may contain, and ids are the caller's.
				":from": avS(formatTime(since)),
				":to":   avS(formatTime(until) + keySepSuccessor),
			},
			ConsistentRead: aws.Bool(true),
		}
		addTelemetryFilter(in, f)

		for {
			page, err := s.api.Query(ctx, in)
			if err != nil {
				return nil, wrap("query telemetry", err)
			}
			for _, m := range page.Items {
				e, err := telemetryFromItem(m)
				if err != nil {
					return nil, err
				}
				out = append(out, e)
				if len(out) >= limit {
					if f.Limit <= 0 && len(out) >= maxTelemetryResults {
						return nil, fmt.Errorf("%w: telemetry query with no Limit matched at least %d events",
							ErrResultTooLarge, maxTelemetryResults)
					}
					return out, nil
				}
			}
			if len(page.LastEvaluatedKey) == 0 {
				break
			}
			in.ExclusiveStartKey = page.LastEvaluatedKey
		}
		in.ExclusiveStartKey = nil
	}
	return out, nil
}

// telemetryRange resolves the filter's open ends against the retention horizon
// and the clock, and refuses a range no realistic query wants. See the file
// header for why the horizon is the default lower bound and not the epoch.
func (s *Store) telemetryRange(f auth.TelemetryFilter) (time.Time, time.Time, bool, error) {
	now := s.nowUTC()
	since, until := f.Since.UTC(), f.Until.UTC()
	if f.Since.IsZero() {
		since = now.Add(-s.telemetryTTL)
	}
	if f.Until.IsZero() {
		until = now
	}
	if until.Before(since) {
		// Not an error, and not a Query either: MemoryTelemetryStore answers an
		// inverted range with an empty result, because every event fails one of
		// its two comparisons. A BETWEEN with reversed bounds is not a shape to
		// hand DynamoDB and find out.
		return time.Time{}, time.Time{}, false, nil
	}
	if days := int(until.Sub(since)/(24*time.Hour)) + 1; days > maxTelemetryDays {
		return time.Time{}, time.Time{}, false, fmt.Errorf("%w: %d days, limit %d",
			ErrTelemetryRangeTooLarge, days, maxTelemetryDays)
	}
	return since, until, true, nil
}

// addTelemetryFilter pushes the two non-key predicates into DynamoDB. They are
// the caller's own filter over a partition the key has already scoped, not a
// tenant check — see the file header on §3.
func addTelemetryFilter(in *awsddb.QueryInput, f auth.TelemetryFilter) {
	var clauses []string
	if f.UserID != "" {
		clauses = append(clauses, "#userId = :userId")
		in.ExpressionAttributeNames["#"+attrUserID] = attrUserID
		in.ExpressionAttributeValues[":userId"] = avS(f.UserID)
	}
	if f.EventName != "" {
		clauses = append(clauses, "#eventName = :eventName")
		in.ExpressionAttributeNames["#"+attrEventName] = attrEventName
		in.ExpressionAttributeValues[":eventName"] = avS(f.EventName)
	}
	if len(clauses) == 0 {
		return
	}
	expr := clauses[0]
	if len(clauses) == 2 {
		expr += " AND " + clauses[1]
	}
	in.FilterExpression = aws.String(expr)
}

// telemetryItem encodes one event (data-model.md §5, "Telemetry event").
//
// success is written even when false: it is the field the whole log exists to
// distinguish on, and an absent one would be indistinguishable from a failure.
// Everything else follows the omission rule.
func (s *Store) telemetryItem(e auth.TelemetryEvent) (item, error) {
	meta, err := anyMapAV(e.Meta)
	if err != nil {
		return nil, err
	}
	return item{}.
		sAlways(attrPK, telemetryPK(e.TenantID, e.Timestamp)).
		sAlways(attrSK, telemetrySK(e.Timestamp, e.ID)).
		stamp(typeTelemetry).
		sAlways(attrEventID, e.ID).
		s(attrEventName, e.EventName).
		s(attrUserID, e.UserID).
		sAlways(attrTenantID, e.TenantID).
		s(attrIP, e.IP).
		s(attrUserAgent, e.UserAgent).
		b(attrSuccess, e.Success).
		s(attrError, e.Error).
		av(attrMeta, meta).
		sAlways(attrCreatedAt, formatTime(e.Timestamp)).
		ttl(e.Timestamp.Add(s.telemetryTTL)), nil
}

func telemetryFromItem(m map[string]types.AttributeValue) (auth.TelemetryEvent, error) {
	if err := checkVersion(m, typeTelemetry); err != nil {
		return auth.TelemetryEvent{}, err
	}
	at, err := getTime(m, attrCreatedAt)
	if err != nil {
		return auth.TelemetryEvent{}, err
	}
	return auth.TelemetryEvent{
		ID:        getS(m, attrEventID),
		EventName: getS(m, attrEventName),
		UserID:    getS(m, attrUserID),
		TenantID:  getS(m, attrTenantID),
		IP:        getS(m, attrIP),
		UserAgent: getS(m, attrUserAgent),
		Success:   getBool(m, attrSuccess),
		Error:     getS(m, attrError),
		Timestamp: at,
		Meta:      anyMapFromAV(m[attrMeta]),
	}, nil
}

// newTelemetryID mints an id for an event that arrived without one, in the shape
// the core's own newID produces; see newWebhookID for why it is minted here.
func newTelemetryID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("dynamodb: mint telemetry id: %w", err)
	}
	return "tel_" + hex.EncodeToString(b), nil
}
