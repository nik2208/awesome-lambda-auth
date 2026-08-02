package config

import (
	"encoding/json"
	"testing"
	"time"
)

// TestParseDuration pins the ms-syntax grammar, including the two places it
// disagrees with Go's time.ParseDuration in opposite directions: "7d" is valid
// here and not in Go, and "1h30m" is valid in Go and not here. Accepting the
// compound form would make the product silently interpret a string the reference
// would have rejected.
func TestParseDuration(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "15m", want: 15 * time.Minute},
		{in: "7d", want: 7 * 24 * time.Hour},
		{in: "24h", want: 24 * time.Hour},
		{in: "30d", want: 30 * 24 * time.Hour},
		{in: "90d", want: 90 * 24 * time.Hour},
		{in: "500ms", want: 500 * time.Millisecond},
		{in: "1000", want: time.Second},
		{in: "1.5h", want: 90 * time.Minute},
		{in: "2 days", want: 48 * time.Hour},
		{in: "1w", want: 7 * 24 * time.Hour},
		{in: " 15m ", want: 15 * time.Minute},
		{in: "15M", want: 15 * time.Minute},

		{in: "1h30m", wantErr: true},
		{in: "", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "10x", wantErr: true},
		{in: "d", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseDuration(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseDuration(%q) = %v, want an error", tc.in, got.Duration())
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDuration(%q): %v", tc.in, err)
			}
			if got.Duration() != tc.want {
				t.Errorf("ParseDuration(%q) = %v, want %v", tc.in, got.Duration(), tc.want)
			}
			if got.String() != tc.in {
				t.Errorf("String() = %q, want the value as written, %q", got.String(), tc.in)
			}
		})
	}
}

// TestDurationUnmarshalRetainsBadValues checks the deliberate design choice:
// decoding must not fail, so that validation can report the problem with the
// knob's dotted path instead of the decoder reporting it without one.
func TestDurationUnmarshalRetainsBadValues(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"1h30m"`), &d); err != nil {
		t.Fatalf("decoding a malformed duration must not fail, got %v", err)
	}
	if d.parseErr() == nil {
		t.Fatal("the parse error was not retained for validation to report")
	}
	if d.String() != "1h30m" {
		t.Errorf("String() = %q, want the raw value so the diagnostic can quote it", d.String())
	}
}

func TestDurationUnmarshalNumberIsMilliseconds(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`60000`), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.Duration() != time.Minute {
		t.Errorf("60000 decoded to %v, want 1m", d.Duration())
	}
}

// TestStringListAcceptsScalarOrArray covers idProvider.jwksCorsOrigins, whose
// reference default is the bare string "*" (src/router/auth.router.ts:492).
func TestStringListAcceptsScalarOrArray(t *testing.T) {
	var scalar StringList
	if err := json.Unmarshal([]byte(`"*"`), &scalar); err != nil {
		t.Fatalf("unmarshal scalar: %v", err)
	}
	if len(scalar.Values) != 1 || scalar.Values[0] != "*" {
		t.Errorf("scalar form decoded to %v", scalar.Values)
	}

	var array StringList
	if err := json.Unmarshal([]byte(`["https://a.example.com","https://b.example.com"]`), &array); err != nil {
		t.Fatalf("unmarshal array: %v", err)
	}
	if len(array.Values) != 2 {
		t.Errorf("array form decoded to %v", array.Values)
	}

	var wrong StringList
	if err := json.Unmarshal([]byte(`42`), &wrong); err != nil {
		t.Fatalf("a type mismatch must be retained, not returned: %v", err)
	}
	if wrong.parseErr() == nil {
		t.Error("the type mismatch was not retained for validation to report")
	}
}
