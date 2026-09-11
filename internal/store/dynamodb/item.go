package dynamodb

import (
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// tsLayout is RFC 3339, UTC, with a fixed nine-digit fraction.
//
// Fixed width is the whole point. DynamoDB compares strings bytewise, and
// time.RFC3339Nano trims trailing zeros from the fraction — so "…:00Z" sorts
// *after* "…:00.5Z" ('Z' > '.'), and lexicographic order stops matching
// chronological order. Both the single-use conditions (<F>Exp > :now) and the
// GSI1 session sort key depend on that equivalence, so the layout must pad.
const tsLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string {
	return t.UTC().Format(tsLayout)
}

// parseTime accepts the current layout and falls back to RFC 3339 with a
// variable fraction, so items written before the padding was pinned still read
// back (the §7 rule that readers tolerate older writers).
func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(tsLayout, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("dynamodb: parse timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

// item is a small builder. Its only real job is the omission rule: an absent
// optional value is left out entirely, never written as NULL, so that
// attribute_not_exists conditions keep meaning what they say (§5).
type item map[string]types.AttributeValue

func (it item) s(name, v string) item {
	if v == "" {
		return it
	}
	it[name] = &types.AttributeValueMemberS{Value: v}
	return it
}

// sAlways writes even the empty string. Used for nothing optional — only for
// attributes whose presence is part of the item's identity.
func (it item) sAlways(name, v string) item {
	it[name] = &types.AttributeValueMemberS{Value: v}
	return it
}

func (it item) n(name string, v int64) item {
	it[name] = &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
	return it
}

func (it item) b(name string, v bool) item {
	it[name] = &types.AttributeValueMemberBOOL{Value: v}
	return it
}

func (it item) t(name string, v time.Time) item {
	if v.IsZero() {
		return it
	}
	return it.s(name, formatTime(v))
}

func (it item) tp(name string, v *time.Time) item {
	if v == nil {
		return it
	}
	return it.t(name, *v)
}

// av sets a prebuilt attribute value. It is for the composite types — a map of
// maps — that the scalar setters above cannot express; the caller owns the
// omission decision.
func (it item) av(name string, v types.AttributeValue) item {
	it[name] = v
	return it
}

// ttl sets the expiry DynamoDB reaps on. TTL is not a security boundary —
// deletion is best-effort within roughly 48 hours — so every read of a
// TTL-bearing item re-checks its expiry attribute in code (§4.5).
func (it item) ttl(at time.Time) item {
	return it.n(attrTTL, at.Unix())
}

func getS(m map[string]types.AttributeValue, name string) string {
	if av, ok := m[name].(*types.AttributeValueMemberS); ok {
		return av.Value
	}
	return ""
}

func getBool(m map[string]types.AttributeValue, name string) bool {
	if av, ok := m[name].(*types.AttributeValueMemberBOOL); ok {
		return av.Value
	}
	return false
}

func getN(m map[string]types.AttributeValue, name string) int64 {
	av, ok := m[name].(*types.AttributeValueMemberN)
	if !ok {
		return 0
	}
	v, err := strconv.ParseInt(av.Value, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func getTime(m map[string]types.AttributeValue, name string) (time.Time, error) {
	raw := getS(m, name)
	if raw == "" {
		return time.Time{}, nil
	}
	return parseTime(raw)
}

func getTimePtr(m map[string]types.AttributeValue, name string) (*time.Time, error) {
	raw := getS(m, name)
	if raw == "" {
		return nil, nil
	}
	t, err := parseTime(raw)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// checkVersion refuses an item a newer build wrote. Forward compatibility is
// promised for added attributes (§7 rule 2), not for a bumped _v, which by
// definition means a reader change was required.
func checkVersion(m map[string]types.AttributeValue, kind string) error {
	if v := getN(m, attrVer); v > schemaVersion {
		return fmt.Errorf("dynamodb: %s item is schema version %d, this build understands %d", kind, v, schemaVersion)
	}
	return nil
}

// stamp writes the two attributes every item carries.
func (it item) stamp(entityType string) item {
	return it.sAlways(attrType, entityType).n(attrVer, schemaVersion)
}

func key(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		attrPK: &types.AttributeValueMemberS{Value: pk},
		attrSK: &types.AttributeValueMemberS{Value: sk},
	}
}

// exprNames aliases every attribute an expression mentions. Doing it
// unconditionally is cheaper than auditing each name against DynamoDB's
// reserved-word list, and the "#attr" aliases keep the expressions readable.
func exprNames(attrs ...string) map[string]string {
	m := make(map[string]string, len(attrs))
	for _, a := range attrs {
		m["#"+a] = a
	}
	return m
}

// itemBytes estimates an item's size the way DynamoDB's own accounting does —
// attribute names plus values, three bytes per map or list plus one per element,
// a number at about a byte per two digits — rounding up wherever the documented
// rule is approximate. Its one caller compares the result against a cap set
// 100 KB under the 400 KB item limit (MaxTemplateBytes), so the estimate has to
// be conservative, not exact: an item that passes here must not be refused there.
func itemBytes(m map[string]types.AttributeValue) int {
	n := 0
	for name, av := range m {
		n += len(name) + attributeBytes(av)
	}
	return n
}

func attributeBytes(av types.AttributeValue) int {
	switch v := av.(type) {
	case *types.AttributeValueMemberS:
		return len(v.Value)
	case *types.AttributeValueMemberN:
		return len(v.Value) + 1
	case *types.AttributeValueMemberB:
		return len(v.Value)
	case *types.AttributeValueMemberBOOL, *types.AttributeValueMemberNULL:
		return 1
	case *types.AttributeValueMemberSS:
		n := 0
		for _, s := range v.Value {
			n += len(s)
		}
		return n
	case *types.AttributeValueMemberNS:
		n := 0
		for _, s := range v.Value {
			n += len(s) + 1
		}
		return n
	case *types.AttributeValueMemberBS:
		n := 0
		for _, b := range v.Value {
			n += len(b)
		}
		return n
	case *types.AttributeValueMemberM:
		n := 3
		for k, e := range v.Value {
			n += len(k) + 1 + attributeBytes(e)
		}
		return n
	case *types.AttributeValueMemberL:
		n := 3
		for _, e := range v.Value {
			n += 1 + attributeBytes(e)
		}
		return n
	}
	return 0
}

func avS(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

func avN(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}
