package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// telemetryStore pins the clock, because every default this store applies — the
// retention horizon, the Until bound, the day bucket an event lands in — is read
// off it, and a test that let it run would be asserting against the wall.
func telemetryStore(t *testing.T, now time.Time, mutate ...func(*Options)) *Store {
	t.Helper()
	opts := append([]func(*Options){func(o *Options) { o.Now = func() time.Time { return now } }}, mutate...)
	store, _ := newStore(t, opts...)
	return store
}

func recordEvent(t *testing.T, store *Store, e auth.TelemetryEvent) {
	t.Helper()
	if err := store.Record(context.Background(), e); err != nil {
		t.Fatalf("record %s: %v", e.ID, err)
	}
}

func eventNames(events []auth.TelemetryEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.ID)
	}
	return out
}

func TestTelemetryRoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	store := telemetryStore(t, now)
	ctx := context.Background()

	want := auth.TelemetryEvent{
		ID:        "tel_one",
		EventName: "login.success",
		UserID:    "usr_1",
		TenantID:  "acme",
		IP:        "203.0.113.7",
		UserAgent: "curl/8",
		Success:   true,
		Timestamp: now.Add(-time.Hour),
		Meta:      map[string]any{"method": "password", "attempts": float64(2)},
	}
	recordEvent(t, store, want)

	got, err := store.Query(ctx, auth.TelemetryFilter{TenantID: "acme"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("query returned %d events, want 1", len(got))
	}
	e := got[0]
	if e.ID != want.ID || e.EventName != want.EventName || e.UserID != want.UserID ||
		e.IP != want.IP || e.UserAgent != want.UserAgent || !e.Success {
		t.Fatalf("scalars lost: %+v", e)
	}
	if !e.Timestamp.Equal(want.Timestamp) {
		t.Fatalf("timestamp = %v, want %v", e.Timestamp, want.Timestamp)
	}
	if e.Meta["method"] != "password" || e.Meta["attempts"] != float64(2) {
		t.Fatalf("meta lost: %#v", e.Meta)
	}
}

// TestRecordSuppliesWhatTheEventDidNotCarry. An empty id would make two events
// in one nanosecond into one event, and a zero timestamp would bucket the event
// into 0001-01-01 where no realistic range reaches it.
func TestRecordSuppliesWhatTheEventDidNotCarry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	store := telemetryStore(t, now)
	ctx := context.Background()

	for range 2 {
		recordEvent(t, store, auth.TelemetryEvent{EventName: "login.success", TenantID: "acme"})
	}
	got, err := store.Query(ctx, auth.TelemetryFilter{TenantID: "acme"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("two id-less events at one instant collapsed into %d", len(got))
	}
	for _, e := range got {
		if e.ID == "" {
			t.Fatalf("no id was minted: %+v", e)
		}
		if !e.Timestamp.Equal(now) {
			t.Fatalf("timestamp = %v, want the store clock %v", e.Timestamp, now)
		}
	}
}

// TestTelemetryQueryDefaultsSpanTheRetention: "no time range" has to mean
// "everything still stored", which is what the memory store's answer means, and
// that only works because the default horizon and the TTL are one number.
func TestTelemetryQueryDefaultsSpanTheRetention(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	store := telemetryStore(t, now, func(o *Options) { o.TelemetryRetention = 72 * time.Hour })
	ctx := context.Background()

	recordEvent(t, store, auth.TelemetryEvent{ID: "tel_old", TenantID: "acme", Timestamp: now.Add(-48 * time.Hour)})
	recordEvent(t, store, auth.TelemetryEvent{ID: "tel_mid", TenantID: "acme", Timestamp: now.Add(-24 * time.Hour)})
	recordEvent(t, store, auth.TelemetryEvent{ID: "tel_new", TenantID: "acme", Timestamp: now.Add(-time.Hour)})
	// Beyond the horizon: the TTL would have reaped it, and the default range
	// does not look for it.
	recordEvent(t, store, auth.TelemetryEvent{ID: "tel_ancient", TenantID: "acme", Timestamp: now.Add(-96 * time.Hour)})

	got, err := store.Query(ctx, auth.TelemetryFilter{TenantID: "acme"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	// Chronological, oldest first, because the sort key leads with the padded
	// timestamp and the days are visited in order.
	want := []string{"tel_old", "tel_mid", "tel_new"}
	if fmt.Sprint(eventNames(got)) != fmt.Sprint(want) {
		t.Fatalf("default range = %v, want %v", eventNames(got), want)
	}
}

func TestTelemetryQueryFilters(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	store := telemetryStore(t, now)
	ctx := context.Background()

	recordEvent(t, store, auth.TelemetryEvent{ID: "tel_a", TenantID: "acme", UserID: "usr_1", EventName: "login.success", Timestamp: now.Add(-3 * time.Hour)})
	recordEvent(t, store, auth.TelemetryEvent{ID: "tel_b", TenantID: "acme", UserID: "usr_2", EventName: "login.success", Timestamp: now.Add(-2 * time.Hour)})
	recordEvent(t, store, auth.TelemetryEvent{ID: "tel_c", TenantID: "acme", UserID: "usr_1", EventName: "login.failure", Timestamp: now.Add(-time.Hour)})
	recordEvent(t, store, auth.TelemetryEvent{ID: "tel_x", TenantID: "globex", UserID: "usr_1", EventName: "login.success", Timestamp: now.Add(-time.Hour)})

	for _, tc := range []struct {
		name   string
		filter auth.TelemetryFilter
		want   []string
	}{
		{"by user", auth.TelemetryFilter{TenantID: "acme", UserID: "usr_1"}, []string{"tel_a", "tel_c"}},
		{"by event name", auth.TelemetryFilter{TenantID: "acme", EventName: "login.success"}, []string{"tel_a", "tel_b"}},
		{"by both", auth.TelemetryFilter{TenantID: "acme", UserID: "usr_1", EventName: "login.success"}, []string{"tel_a"}},
		{"by range", auth.TelemetryFilter{TenantID: "acme", Since: now.Add(-150 * time.Minute)}, []string{"tel_b", "tel_c"}},
		{"limit", auth.TelemetryFilter{TenantID: "acme", Limit: 2}, []string{"tel_a", "tel_b"}},
		// The tenant is part of the key, so no filter can reach across it.
		{"another tenant", auth.TelemetryFilter{TenantID: "globex"}, []string{"tel_x"}},
		// An inverted range is an empty result and not an error, because every
		// event fails one of the memory store's two comparisons.
		{"inverted range", auth.TelemetryFilter{TenantID: "acme", Since: now, Until: now.Add(-time.Hour)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.Query(ctx, tc.filter)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if fmt.Sprint(eventNames(got)) != fmt.Sprint(append([]string{}, tc.want...)) {
				t.Fatalf("= %v, want %v", eventNames(got), tc.want)
			}
		})
	}
}

// TestTelemetryTenantIsALiteralNotAWildcard is the registered deviation. In a
// single-tenant deployment it is unobservable; in a multi-tenant one the store
// refuses rather than silently answering for one tenant.
func TestTelemetryTenantIsALiteralNotAWildcard(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	t.Run("single-tenant - indistinguishable", func(t *testing.T) {
		store := telemetryStore(t, now)
		recordEvent(t, store, auth.TelemetryEvent{ID: "tel_a", Timestamp: now.Add(-time.Hour)})
		got, err := store.Query(ctx, auth.TelemetryFilter{})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("the untenanted deployment's own events were not returned: %v", eventNames(got))
		}
	})

	t.Run("multi-tenant - refused rather than answered for one tenant", func(t *testing.T) {
		store := telemetryStore(t, now, func(o *Options) { o.MultiTenant = true })
		if _, err := store.Query(ctx, auth.TelemetryFilter{}); !errors.Is(err, ErrTenantRequired) {
			t.Fatalf("untenanted query under multi-tenancy = %v, want ErrTenantRequired", err)
		}
		if err := store.Record(ctx, auth.TelemetryEvent{ID: "tel_x"}); !errors.Is(err, ErrTenantRequired) {
			t.Fatalf("untenanted record under multi-tenancy = %v, want ErrTenantRequired", err)
		}
	})
}

func TestTelemetryRefusals(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	store := telemetryStore(t, now)
	ctx := context.Background()

	t.Run("a range longer than any query wants", func(t *testing.T) {
		_, err := store.Query(ctx, auth.TelemetryFilter{
			TenantID: "acme",
			Since:    now.Add(-2 * 366 * 24 * time.Hour),
			Until:    now,
		})
		if !errors.Is(err, ErrTelemetryRangeTooLarge) {
			t.Fatalf("= %v, want ErrTelemetryRangeTooLarge", err)
		}
	})

	t.Run("meta with no representation", func(t *testing.T) {
		err := store.Record(ctx, auth.TelemetryEvent{
			ID: "tel_bad", TenantID: "acme", Timestamp: now,
			Meta: map[string]any{"fn": func() {}},
		})
		if !errors.Is(err, ErrUnsupportedValue) {
			t.Fatalf("= %v, want ErrUnsupportedValue", err)
		}
	})
}

// TestTelemetryCarriesATTL. This is the one item type written on an
// unauthenticated request path, so it has to expire on its own.
func TestTelemetryCarriesATTL(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	store, client := newStore(t, func(o *Options) {
		o.Now = func() time.Time { return now }
		o.TelemetryRetention = 72 * time.Hour
	})
	at := now.Add(-time.Hour)
	recordEvent(t, store, auth.TelemetryEvent{ID: "tel_ttl", TenantID: "acme", Timestamp: at})

	m := rawItem(t, client, store.table, telemetryPK("acme", at), telemetrySK(at, "tel_ttl"))
	if len(m) == 0 {
		t.Fatal("the event did not land where its key says it should")
	}
	// Seconds, not milliseconds: a millisecond value is not an error DynamoDB
	// reports, it just means the item never expires.
	if got, want := getN(m, attrTTL), at.Add(72*time.Hour).Unix(); got != want {
		t.Fatalf("ttl = %d, want %d", got, want)
	}
}
