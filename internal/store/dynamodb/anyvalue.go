package dynamodb

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// The codec for the three places the core's interfaces carry an uninterpreted
// value: UserMetadataStore's map[string]any, auth.Tenant.Config and
// auth.TelemetryEvent.Meta.
//
// data-model.md §5 specified this as "`attributevalue` marshalling of `any`",
// naming the AWS SDK's reflection-based marshaller. That module is not a
// dependency of this build and is not added for three methods: it is a separate
// Go module with its own release cadence, it marshals Go *structs* — which is
// the half nothing here needs, since every value that reaches these methods
// arrived as JSON — and its zero-value and nil-map conventions are its own
// rather than this table's. What is actually needed is a JSON-shaped codec, and
// that is what this is. §5 is corrected to say so.
//
// # The domain is JSON, deliberately
//
// Every value that reaches these three seams came off the wire as JSON: the
// admin metadata route decodes a request body, the tenant config is a stored
// document, and a telemetry event's meta is a POSTed object. So the domain is
// the JSON value set — null, bool, string, number, array, object — plus the Go
// integer and float kinds a caller inside this process might hand over directly,
// plus []byte and time.Time as the two conveniences that would otherwise
// round-trip as garbage. Anything else is refused at the boundary with
// ErrUnsupportedValue rather than dropped, which is §5's rule.
//
// # Numbers come back as float64, and that is a decision rather than an accident
//
// DynamoDB has one numeric type. A value written from an int and read back has
// to be decoded as *something*, and float64 is what encoding/json produces for a
// number decoded into an `any` — so it is the type the caller's value already
// had on the way in, and the type the reference's own JSON round trip produces.
// Decoding some numbers to int64 and others to float64, by inspecting the
// stored digits, would make the type of a value depend on whether it happened to
// have a fractional part.
//
// The cost is that float64 holds integers exactly only up to 2^53. Rather than
// lose precision silently, an integer beyond that range is **refused** on write:
// a caller with a 64-bit identifier to store should store it as a string, and a
// typed error saying so is better than a value that reads back off by one.
//
// NaN and ±Inf are refused for a simpler reason: DynamoDB's N cannot represent
// them, and JSON cannot either.

// ErrUnsupportedValue means a caller-supplied value has no DynamoDB
// representation this store is willing to invent one for. Nothing was written.
var ErrUnsupportedValue = errors.New("dynamodb: value cannot be stored")

// maxExactInt is 2^53: the largest integer a float64 holds exactly, and
// therefore the largest this codec will accept, since float64 is what it decodes
// numbers back to.
const maxExactInt = 1 << 53

// anyAV encodes a JSON-shaped value.
func anyAV(v any) (types.AttributeValue, error) {
	switch t := v.(type) {
	case nil:
		// A NULL, not an omitted attribute. This codec encodes *values*, and a
		// metadata key explicitly set to null is a key that exists — which is
		// exactly the distinction the omission rule elsewhere in this package
		// relies on the absence of. The item builder's `s`/`t`/`tp` helpers omit;
		// this does not, because here there is nothing to omit into: the value is
		// the whole attribute.
		return &types.AttributeValueMemberNULL{Value: true}, nil
	case bool:
		return &types.AttributeValueMemberBOOL{Value: t}, nil
	case string:
		return &types.AttributeValueMemberS{Value: t}, nil
	case []byte:
		return &types.AttributeValueMemberB{Value: t}, nil
	case time.Time:
		// As the padded RFC 3339 string every other timestamp in this table uses,
		// so a value that happens to be a time sorts and compares like one. It
		// decodes back as a string, not as a time.Time: nothing records that the
		// attribute meant an instant, and guessing from the shape of a string
		// would turn any caller's ISO-looking value into a time.
		return &types.AttributeValueMemberS{Value: formatTime(t)}, nil
	case json.Number:
		return &types.AttributeValueMemberN{Value: t.String()}, nil
	case float32:
		return floatAV(float64(t))
	case float64:
		return floatAV(t)
	case int:
		return intAV(int64(t))
	case int8:
		return intAV(int64(t))
	case int16:
		return intAV(int64(t))
	case int32:
		return intAV(int64(t))
	case int64:
		return intAV(t)
	case uint:
		return uintAV(uint64(t))
	case uint8:
		return uintAV(uint64(t))
	case uint16:
		return uintAV(uint64(t))
	case uint32:
		return uintAV(uint64(t))
	case uint64:
		return uintAV(t)
	case []any:
		out := make([]types.AttributeValue, 0, len(t))
		for i, e := range t {
			av, err := anyAV(e)
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			out = append(out, av)
		}
		return &types.AttributeValueMemberL{Value: out}, nil
	case []string:
		// An L of S rather than an SS, for stringListAV's reasons: DynamoDB
		// forbids an empty SS, and an SS would silently deduplicate and reorder a
		// list the caller wrote as an array.
		return stringListAV(t), nil
	case map[string]any:
		out := make(map[string]types.AttributeValue, len(t))
		for k, e := range t {
			if k == "" {
				return nil, fmt.Errorf("%w: empty map key", ErrUnsupportedValue)
			}
			av, err := anyAV(e)
			if err != nil {
				return nil, fmt.Errorf("key %q: %w", k, err)
			}
			out[k] = av
		}
		return &types.AttributeValueMemberM{Value: out}, nil
	}
	return nil, fmt.Errorf("%w: %T", ErrUnsupportedValue, v)
}

func floatAV(f float64) (types.AttributeValue, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, fmt.Errorf("%w: %v has no DynamoDB number representation", ErrUnsupportedValue, f)
	}
	return &types.AttributeValueMemberN{Value: strconv.FormatFloat(f, 'f', -1, 64)}, nil
}

func intAV(i int64) (types.AttributeValue, error) {
	if i > maxExactInt || i < -maxExactInt {
		return nil, exactnessError(strconv.FormatInt(i, 10))
	}
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(i, 10)}, nil
}

func uintAV(u uint64) (types.AttributeValue, error) {
	if u > maxExactInt {
		return nil, exactnessError(strconv.FormatUint(u, 10))
	}
	return &types.AttributeValueMemberN{Value: strconv.FormatUint(u, 10)}, nil
}

func exactnessError(v string) error {
	return fmt.Errorf("%w: %s is beyond 2^53 and would not read back exactly, because this codec decodes every number as float64; store it as a string", ErrUnsupportedValue, v)
}

// anyFromAV is the inverse. An attribute of a type this build does not
// understand decodes to nil rather than failing the read, which is §7's rule
// that readers tolerate what they do not understand — the alternative is that
// one hand-edited attribute makes a user's whole metadata unreadable.
func anyFromAV(av types.AttributeValue) any {
	switch t := av.(type) {
	case *types.AttributeValueMemberNULL:
		return nil
	case *types.AttributeValueMemberBOOL:
		return t.Value
	case *types.AttributeValueMemberS:
		return t.Value
	case *types.AttributeValueMemberB:
		return t.Value
	case *types.AttributeValueMemberN:
		f, err := strconv.ParseFloat(t.Value, 64)
		if err != nil {
			return nil
		}
		return f
	case *types.AttributeValueMemberL:
		out := make([]any, 0, len(t.Value))
		for _, e := range t.Value {
			out = append(out, anyFromAV(e))
		}
		return out
	case *types.AttributeValueMemberM:
		out := make(map[string]any, len(t.Value))
		for k, e := range t.Value {
			out[k] = anyFromAV(e)
		}
		return out
	case *types.AttributeValueMemberSS:
		// Written by nothing in this codec — the role definition's permissions
		// are the table's only SS — but decoded anyway, because a document
		// migrated from another writer can hold one and returning nil for it
		// would look like data loss.
		out := make([]any, 0, len(t.Value))
		for _, v := range t.Value {
			out = append(out, v)
		}
		return out
	case *types.AttributeValueMemberNS:
		out := make([]any, 0, len(t.Value))
		for _, v := range t.Value {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			out = append(out, f)
		}
		return out
	}
	return nil
}

// anyMapAV encodes a map[string]any as an M, and anyMapFromAV decodes one. A nil
// map encodes as an empty M rather than as an absent attribute, because the two
// callers that use it — the tenant config and a telemetry event's meta — both
// treat absent and empty as the same thing, and writing the attribute
// unconditionally keeps the item shape uniform for a migration sweep.
func anyMapAV(in map[string]any) (types.AttributeValue, error) {
	out := make(map[string]types.AttributeValue, len(in))
	for k, v := range in {
		if k == "" {
			return nil, fmt.Errorf("%w: empty map key", ErrUnsupportedValue)
		}
		av, err := anyAV(v)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", k, err)
		}
		out[k] = av
	}
	return &types.AttributeValueMemberM{Value: out}, nil
}

// anyMapFromAV returns nil for an absent or unreadable attribute, so a record
// that never carried one comes back with a nil map rather than an empty one —
// which is what auth.Tenant and auth.TelemetryEvent look like before they are
// stored.
func anyMapFromAV(av types.AttributeValue) map[string]any {
	m, ok := av.(*types.AttributeValueMemberM)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(m.Value))
	for k, v := range m.Value {
		out[k] = anyFromAV(v)
	}
	return out
}
