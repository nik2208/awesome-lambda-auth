package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestMetadataMergesRatherThanReplaces(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	user := uniqueID("usr")

	if err := store.UpdateMetadata(ctx, user, map[string]any{"a": "one", "b": "two"}); err != nil {
		t.Fatalf("first update: %v", err)
	}
	// The reference's update is a per-key write over whatever is stored, so "a"
	// moves and "b" stays. A store that replaced the document would drop "b".
	if err := store.UpdateMetadata(ctx, user, map[string]any{"a": "moved", "c": "three"}); err != nil {
		t.Fatalf("second update: %v", err)
	}

	got, err := store.GetMetadata(ctx, user)
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	want := map[string]any{"a": "moved", "b": "two", "c": "three"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("metadata = %v, want the merge %v", got, want)
	}
}

func TestMetadataEmptyCases(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	user := uniqueID("usr")

	// A user with nothing stored answers an empty map and no error, never nil,
	// so the value encodes as {} rather than null.
	got, err := store.GetMetadata(ctx, user)
	if err != nil {
		t.Fatalf("get metadata for an empty user: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("empty metadata = %#v, want a non-nil empty map", got)
	}
	// An empty update and a clear of nothing are both no-ops, matching the
	// memory store's empty range and unconditional delete.
	if err := store.UpdateMetadata(ctx, user, nil); err != nil {
		t.Fatalf("empty update: %v", err)
	}
	if err := store.ClearMetadata(ctx, user); err != nil {
		t.Fatalf("clear of nothing: %v", err)
	}
}

func TestMetadataValueRoundTrip(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	user := uniqueID("usr")

	in := map[string]any{
		"string": "hello",
		"bool":   true,
		"int":    42,
		"float":  1.5,
		"null":   nil,
		"list":   []any{"a", float64(1), false},
		"nested": map[string]any{"deep": map[string]any{"deeper": "value"}},
	}
	if err := store.UpdateMetadata(ctx, user, in); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := store.GetMetadata(ctx, user)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if got["string"] != "hello" || got["bool"] != true {
		t.Fatalf("scalars lost: %#v", got)
	}
	// Every number decodes as float64, including the one written from an int.
	// That is the type it would have had coming off the wire as JSON, and the
	// type this codec documents.
	if n, ok := got["int"].(float64); !ok || n != 42 {
		t.Fatalf("int decoded as %T (%v), want float64 42", got["int"], got["int"])
	}
	if n, ok := got["float"].(float64); !ok || n != 1.5 {
		t.Fatalf("float decoded as %T (%v)", got["float"], got["float"])
	}
	// An explicit null is a key that exists with no value, not an absent key.
	if v, present := got["null"]; !present || v != nil {
		t.Fatalf("explicit null lost: present=%v value=%#v", present, v)
	}
	if fmt.Sprint(got["list"]) != fmt.Sprint(in["list"]) {
		t.Fatalf("list = %#v, want %#v", got["list"], in["list"])
	}
	nested, ok := got["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested map decoded as %T", got["nested"])
	}
	deep, ok := nested["deep"].(map[string]any)
	if !ok || deep["deeper"] != "value" {
		t.Fatalf("nesting lost: %#v", nested)
	}
}

func TestMetadataRefusesWhatItCannotStore(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	user := uniqueID("usr")

	t.Run("a value with no representation", func(t *testing.T) {
		err := store.UpdateMetadata(ctx, user, map[string]any{"ch": make(chan int)})
		if !errors.Is(err, ErrUnsupportedValue) {
			t.Fatalf("channel value = %v, want ErrUnsupportedValue", err)
		}
	})

	t.Run("an integer beyond float64's exact range", func(t *testing.T) {
		// Refused rather than stored and silently rounded: this codec decodes
		// every number as float64, so a 64-bit id would not read back.
		err := store.UpdateMetadata(ctx, user, map[string]any{"snowflake": int64(1) << 60})
		if !errors.Is(err, ErrUnsupportedValue) {
			t.Fatalf("large int = %v, want ErrUnsupportedValue", err)
		}
	})

	t.Run("an oversize entry", func(t *testing.T) {
		err := store.UpdateMetadata(ctx, user, map[string]any{
			"big": strings.Repeat("x", MaxMetadataValueBytes+1),
		})
		if !errors.Is(err, ErrMetadataTooLarge) {
			t.Fatalf("oversize entry = %v, want ErrMetadataTooLarge", err)
		}
	})

	t.Run("nothing was written by any of them", func(t *testing.T) {
		got, err := store.GetMetadata(ctx, user)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("a refused update left %v behind", got)
		}
	})
}

// TestMetadataIsNotTenantScopedAndCannotBe. UserMetadataStore's methods carry no
// tenant, so the partition is keyed on the user id alone; this pins that the
// same user id reaches the same metadata whatever tenant the caller is thinking
// of, because there is no tenant in the key to disagree about.
func TestMetadataIsNotTenantScopedAndCannotBe(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t, func(o *Options) { o.MultiTenant = true })
	ctx := context.Background()
	user := uniqueID("usr")

	if err := store.UpdateMetadata(ctx, user, map[string]any{"k": "v"}); err != nil {
		t.Fatalf("update under multi-tenancy: %v", err)
	}
	got, err := store.GetMetadata(ctx, user)
	if err != nil {
		t.Fatalf("get under multi-tenancy: %v", err)
	}
	if got["k"] != "v" {
		t.Fatalf("metadata = %v, want the value back", got)
	}
}

func TestClearMetadataAndDeleteUserBothSweepThePartition(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	t.Run("clear", func(t *testing.T) {
		user := uniqueID("usr")
		if err := store.UpdateMetadata(ctx, user, map[string]any{"a": 1, "b": 2}); err != nil {
			t.Fatalf("update: %v", err)
		}
		if err := store.ClearMetadata(ctx, user); err != nil {
			t.Fatalf("clear: %v", err)
		}
		got, err := store.GetMetadata(ctx, user)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("clear left %v", got)
		}
	})

	t.Run("delete user", func(t *testing.T) {
		user := sampleUser("acme")
		if _, err := store.CreateUser(ctx, user); err != nil {
			t.Fatalf("create user: %v", err)
		}
		if err := store.UpdateMetadata(ctx, user.ID, map[string]any{"a": 1}); err != nil {
			t.Fatalf("update: %v", err)
		}
		if err := store.DeleteUser(ctx, user.ID, "acme"); err != nil {
			t.Fatalf("delete user: %v", err)
		}
		// Metadata lives outside the user's item collection now, so nothing
		// deletes it implicitly: DeleteUser has to sweep the second partition.
		got, err := store.GetMetadata(ctx, user.ID)
		if err != nil {
			t.Fatalf("get after delete: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("DeleteUser left metadata behind: %v", got)
		}
	})
}
