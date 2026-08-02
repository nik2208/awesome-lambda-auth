package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a time span written in the syntax the reference uses for every TTL
// knob: the npm "ms" grammar, as in "15m", "7d", "30d", "24h".
//
// This is not Go's time.ParseDuration syntax and the two disagree in both
// directions: ms accepts "7d" (Go does not) and Go accepts "1h30m" (ms does
// not, because it matches a single number-and-unit term and returns undefined
// for anything else). Both quirks are reproduced, because the values in a
// deployed document are the same strings operators copy out of the reference's
// documentation, and quietly reinterpreting "1h30m" as 90 minutes when the
// reference would have thrown is exactly the silent divergence the wire-contract
// discipline exists to prevent.
//
// A malformed value does not fail at decode time. It is retained together with
// its parse error and reported by validation as RS-9, so the operator gets the
// dotted path of the offending knob rather than a bare "invalid character 'd'".
type Duration struct {
	raw string
	d   time.Duration
	err error
}

// ParseDuration parses one ms-syntax term. A bare number is milliseconds, which
// is what ms does.
func ParseDuration(s string) (Duration, error) {
	d := Duration{raw: s}
	d.d, d.err = parseMS(s)
	return d, d.err
}

// mustDuration is for defaults, which are compile-time constants from the
// reference and cannot fail.
func mustDuration(s string) Duration {
	d, err := ParseDuration(s)
	if err != nil {
		panic("config: bad built-in default duration " + strconv.Quote(s) + ": " + err.Error())
	}
	return d
}

// Duration returns the parsed span. It is zero when the value did not parse; the
// accompanying RS-9 diagnostic prevents such a Config from ever being returned
// by Load.
func (d Duration) Duration() time.Duration { return d.d }

// String returns the value as the operator wrote it, which is what belongs in a
// diagnostic.
func (d Duration) String() string { return d.raw }

// IsZero reports whether the knob was left unset.
func (d Duration) IsZero() bool { return d.raw == "" }

// err reports the retained parse error, if any.
func (d Duration) parseErr() error { return d.err }

// UnmarshalJSON accepts a quoted ms-syntax string or a bare number of
// milliseconds. It never fails: a malformed value is retained for validation to
// report with its path (see the type comment).
func (d *Duration) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, `"`) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*d = Duration{raw: s}
		d.d, d.err = parseMS(s)
		return nil
	}
	var n float64
	if err := json.Unmarshal(data, &n); err != nil {
		*d = Duration{raw: trimmed, err: fmt.Errorf("expected an ms-syntax string such as \"15m\", or a number of milliseconds")}
		return nil
	}
	*d = Duration{raw: trimmed, d: time.Duration(n) * time.Millisecond}
	return nil
}

// MarshalJSON emits the value as the operator wrote it, so a document that is
// read and written back round-trips unchanged.
func (d Duration) MarshalJSON() ([]byte, error) {
	if d.raw == "" {
		return []byte(`""`), nil
	}
	return json.Marshal(d.raw)
}

// msUnits maps every unit spelling the ms package accepts to its span. The long
// spellings matter: "1 day" is valid ms input and appears in the reference's own
// documentation.
var msUnits = map[string]time.Duration{
	"":             time.Millisecond,
	"ms":           time.Millisecond,
	"msec":         time.Millisecond,
	"msecs":        time.Millisecond,
	"millisecond":  time.Millisecond,
	"milliseconds": time.Millisecond,
	"s":            time.Second,
	"sec":          time.Second,
	"secs":         time.Second,
	"second":       time.Second,
	"seconds":      time.Second,
	"m":            time.Minute,
	"min":          time.Minute,
	"mins":         time.Minute,
	"minute":       time.Minute,
	"minutes":      time.Minute,
	"h":            time.Hour,
	"hr":           time.Hour,
	"hrs":          time.Hour,
	"hour":         time.Hour,
	"hours":        time.Hour,
	"d":            24 * time.Hour,
	"day":          24 * time.Hour,
	"days":         24 * time.Hour,
	"w":            7 * 24 * time.Hour,
	"week":         7 * 24 * time.Hour,
	"weeks":        7 * 24 * time.Hour,
	"y":            365 * 24 * time.Hour,
	"year":         365 * 24 * time.Hour,
	"years":        365 * 24 * time.Hour,
}

// parseMS parses a single ms-syntax term: an optional sign, a decimal number,
// optional whitespace, and an optional unit. Compound spans such as "1h30m" are
// rejected, matching ms.
func parseMS(s string) (time.Duration, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, fmt.Errorf("empty value")
	}

	i := 0
	if trimmed[i] == '+' || trimmed[i] == '-' {
		i++
	}
	start := i
	for i < len(trimmed) && (trimmed[i] >= '0' && trimmed[i] <= '9') {
		i++
	}
	if i < len(trimmed) && trimmed[i] == '.' {
		i++
		for i < len(trimmed) && (trimmed[i] >= '0' && trimmed[i] <= '9') {
			i++
		}
	}
	if i == start {
		return 0, fmt.Errorf("no number in %q", s)
	}

	n, err := strconv.ParseFloat(trimmed[:i], 64)
	if err != nil {
		return 0, fmt.Errorf("cannot read the number in %q", s)
	}

	unit := strings.ToLower(strings.TrimSpace(trimmed[i:]))
	span, ok := msUnits[unit]
	if !ok {
		return 0, fmt.Errorf("unknown unit %q; use ms, s, m, h, d, w or y (one term only, not %q)", unit, s)
	}
	return time.Duration(n * float64(span)), nil
}

// StringList is a knob that accepts either a single string or an array of them.
// The reference does this for idProvider.jwksCorsOrigins, whose default is the
// bare string "*" (src/router/auth.router.ts:492).
type StringList struct {
	Values []string
	err    error
}

// UnmarshalJSON accepts a string, an array of strings, or null. As with
// Duration, a type mismatch is retained rather than returned so that validation
// can name the knob.
func (l *StringList) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, `"`) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*l = StringList{Values: []string{s}}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		*l = StringList{err: fmt.Errorf("expected a string or an array of strings")}
		return nil
	}
	*l = StringList{Values: many}
	return nil
}

// MarshalJSON always emits the array form; the scalar form is an input
// convenience, not something worth preserving.
func (l StringList) MarshalJSON() ([]byte, error) {
	if l.Values == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(l.Values)
}

func (l StringList) parseErr() error { return l.err }
