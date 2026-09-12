package dynamodb

import (
	"context"
	"fmt"
	"sort"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// boolPtr, intPtr and strPtr live in settings_test.go and templates_test.go;
// this file uses them for the same reason those do, which is that every optional
// field of a webhook configuration is a pointer whose nil is a value.

func addWebhook(t *testing.T, store *Store, c auth.WebhookConfig) auth.WebhookConfig {
	t.Helper()
	got, err := store.AddWebhook(context.Background(), c)
	if err != nil {
		t.Fatalf("add webhook: %v", err)
	}
	if got.ID == "" {
		t.Fatal("AddWebhook returned no id")
	}
	return got
}

// TestFindByEventIsTheOnlyFilterInTheChain. The emit path hands every
// configuration this returns straight to the sender, which re-checks neither
// isActive nor events, so over-returning delivers.
func TestFindByEventIsTheOnlyFilterInTheChain(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	global := addWebhook(t, store, auth.WebhookConfig{URL: "https://g.example.test", Events: []string{"user.created"}})
	acme := addWebhook(t, store, auth.WebhookConfig{URL: "https://a.example.test", Events: []string{"user.created"}, TenantID: "acme"})
	other := addWebhook(t, store, auth.WebhookConfig{URL: "https://o.example.test", Events: []string{"user.created"}, TenantID: "globex"})
	off := addWebhook(t, store, auth.WebhookConfig{URL: "https://x.example.test", Events: []string{"user.created"}, IsActive: boolPtr(false)})
	wildcard := addWebhook(t, store, auth.WebhookConfig{URL: "https://w.example.test", Events: []string{auth.WebhookEventWildcard}})
	noEvents := addWebhook(t, store, auth.WebhookConfig{URL: "https://n.example.test"})
	otherEvent := addWebhook(t, store, auth.WebhookConfig{URL: "https://e.example.test", Events: []string{"user.deleted"}})

	got, err := store.FindByEvent(ctx, "user.created", "acme")
	if err != nil {
		t.Fatalf("find by event: %v", err)
	}
	ids := map[string]bool{}
	for _, c := range got {
		ids[c.ID] = true
	}
	// A non-empty tenant gets its own subscriptions and the global ones.
	for _, want := range []string{global.ID, acme.ID, wildcard.ID} {
		if !ids[want] {
			t.Fatalf("missing a subscription that should have been delivered to: %v", got)
		}
	}
	// Every one of these would be a delivery to the wrong place.
	for name, id := range map[string]string{
		"another tenant's":   other.ID,
		"a deactivated one":  off.ID,
		"one with no events": noEvents.ID,
		"a different event":  otherEvent.ID,
	} {
		if ids[id] {
			t.Fatalf("FindByEvent returned %s subscription", name)
		}
	}

	// An empty tenant gets the global ones only, which is what the interface's
	// own example query does.
	got, err = store.FindByEvent(ctx, "user.created", "")
	if err != nil {
		t.Fatalf("find by event, no tenant: %v", err)
	}
	for _, c := range got {
		if c.TenantID != "" {
			t.Fatalf("a tenant-scoped subscription answered an untenanted event: %+v", c)
		}
	}
}

// TestWebhookNilAndEmptyAreDifferentValues. nil means "key absent" and the
// defaults apply; an empty non-nil slice is the administrator having cleared the
// list. The settings store solved this with an L and so does this one.
func TestWebhookNilAndEmptyAreDifferentValues(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	bare := addWebhook(t, store, auth.WebhookConfig{URL: "https://b.example.test"})
	full := addWebhook(t, store, auth.WebhookConfig{
		URL:            "https://f.example.test",
		Events:         []string{},
		AllowedActions: []string{},
		IsActive:       boolPtr(false),
		MaxRetries:     intPtr(0),
		RetryDelayMs:   intPtr(0),
	})

	page, err := store.ListWebhooks(ctx, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byID := map[string]auth.WebhookConfig{}
	for _, c := range page {
		byID[c.ID] = c
	}

	b := byID[bare.ID]
	if b.Events != nil || b.AllowedActions != nil || b.IsActive != nil || b.MaxRetries != nil || b.RetryDelayMs != nil {
		t.Fatalf("absent keys came back present: %#v", b)
	}
	// The defaults the core resolves at the point of use, which only work
	// because nil survived the round trip.
	if !b.Active() || b.Retries() != auth.DefaultWebhookMaxRetries || b.RetryDelay() != auth.DefaultWebhookRetryDelay {
		t.Fatalf("resolved defaults are wrong for an absent-key config: %v %d %v", b.Active(), b.Retries(), b.RetryDelay())
	}

	f := byID[full.ID]
	if f.Events == nil || len(f.Events) != 0 || f.AllowedActions == nil || len(f.AllowedActions) != 0 {
		t.Fatalf("cleared lists came back as %#v / %#v, want empty non-nil", f.Events, f.AllowedActions)
	}
	// maxRetries: 0 is "deliver once, never retry" and must not decay into
	// "retry three times".
	if f.Active() || f.Retries() != 0 || f.RetryDelay() != 0 {
		t.Fatalf("explicit zeroes decayed into defaults: %v %d %v", f.Active(), f.Retries(), f.RetryDelay())
	}
}

func TestWebhookPatchSemantics(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	c := addWebhook(t, store, auth.WebhookConfig{
		URL:      "https://a.example.test",
		Events:   []string{"user.created", "user.deleted"},
		Secret:   "s3cret",
		TenantID: "acme",
		IsActive: boolPtr(true),
	})

	// A pointer to a zero value sets that zero — this is how the admin toggle
	// turns a webhook off — while every field the patch does not name is left
	// alone.
	if err := store.UpdateWebhook(ctx, c.ID, auth.WebhookPatch{IsActive: boolPtr(false)}); err != nil {
		t.Fatalf("patch isActive: %v", err)
	}
	got := mustGetWebhook(t, store, c.ID)
	if got.Active() {
		t.Fatal("the off toggle did not take")
	}
	if got.URL != c.URL || got.Secret != c.Secret || got.TenantID != c.TenantID ||
		fmt.Sprint(got.Events) != fmt.Sprint(c.Events) {
		t.Fatalf("an unnamed field moved: %+v", got)
	}

	// A non-nil slice replaces the stored one whole rather than appending, so a
	// caller changing one event sends the list back complete.
	if err := store.UpdateWebhook(ctx, c.ID, auth.WebhookPatch{Events: []string{"user.updated"}}); err != nil {
		t.Fatalf("patch events: %v", err)
	}
	got = mustGetWebhook(t, store, c.ID)
	if fmt.Sprint(got.Events) != fmt.Sprint([]string{"user.updated"}) {
		t.Fatalf("events = %v, want a whole replacement", got.Events)
	}

	// A non-nil empty slice clears.
	if err := store.UpdateWebhook(ctx, c.ID, auth.WebhookPatch{Events: []string{}}); err != nil {
		t.Fatalf("clear events: %v", err)
	}
	got = mustGetWebhook(t, store, c.ID)
	if got.Events == nil || len(got.Events) != 0 {
		t.Fatalf("events = %#v, want empty non-nil", got.Events)
	}

	// A pointer to the empty string sets the empty string.
	if err := store.UpdateWebhook(ctx, c.ID, auth.WebhookPatch{Secret: strPtr("")}); err != nil {
		t.Fatalf("clear secret: %v", err)
	}
	if got = mustGetWebhook(t, store, c.ID); got.Secret != "" {
		t.Fatalf("secret = %q, want cleared", got.Secret)
	}

	// An id the store does not hold is not an error: the route answers success
	// without asking whether anything changed.
	if err := store.UpdateWebhook(ctx, "whk_ghost", auth.WebhookPatch{URL: strPtr("https://x")}); err != nil {
		t.Fatalf("patch unknown id: %v", err)
	}
}

func TestRemoveWebhookIsIdempotent(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	c := addWebhook(t, store, auth.WebhookConfig{URL: "https://a.example.test", Events: []string{"*"}})
	if err := store.RemoveWebhook(ctx, c.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	// A second DELETE of the same id succeeds, as it does in the reference.
	if err := store.RemoveWebhook(ctx, c.ID); err != nil {
		t.Fatalf("second remove: %v", err)
	}
	page, err := store.ListWebhooks(ctx, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page) != 0 {
		t.Fatalf("remove left %+v", page)
	}
}

// TestListWebhooksIsIDOrdered pins the registered deviation: the core's
// normative order is first-insertion and a Query returns a partition in sort-key
// order, whose tail is a random id.
func TestListWebhooksIsIDOrdered(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	var ids []string
	for i := range 5 {
		c := addWebhook(t, store, auth.WebhookConfig{
			URL:    fmt.Sprintf("https://%d.example.test", i),
			Events: []string{"*"},
		})
		ids = append(ids, c.ID)
	}
	sort.Strings(ids)

	page, err := store.ListWebhooks(ctx, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var got []string
	for _, c := range page {
		got = append(got, c.ID)
	}
	if fmt.Sprint(got) != fmt.Sprint(ids) {
		t.Fatalf("ListWebhooks = %v, want id-ascending %v", got, ids)
	}

	// The paging rules are the ones the core states for every offset listing.
	if page, err = store.ListWebhooks(ctx, 0, 0); err != nil || len(page) != 0 {
		t.Fatalf("limit 0 = %v (%v), want an empty page and no error", page, err)
	}
	if page, err = store.ListWebhooks(ctx, 10, 99); err != nil || len(page) != 0 {
		t.Fatalf("offset past the end = %v (%v), want empty", page, err)
	}
	if page, err = store.ListWebhooks(ctx, 2, 1); err != nil {
		t.Fatalf("page: %v", err)
	} else if fmt.Sprint([]string{page[0].ID, page[1].ID}) != fmt.Sprint(ids[1:3]) {
		t.Fatalf("page at offset 1 = %v, want %v", page, ids[1:3])
	}
}

// TestFindByProviderDoesNotFilterOnIsActive is reproduced upstream behaviour and
// deliberately not corrected: deactivating a webhook stops outgoing deliveries
// and does not stop an inbound script from running.
func TestFindByProviderDoesNotFilterOnIsActive(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	addWebhook(t, store, auth.WebhookConfig{
		URL:            "https://in.example.test",
		Provider:       "stripe",
		AllowedActions: []string{"user.create"},
		JSScript:       "return { action: 'user.create' }",
		IsActive:       boolPtr(false),
	})

	got, ok, err := store.FindByProvider(ctx, "stripe")
	if err != nil {
		t.Fatalf("find by provider: %v", err)
	}
	if !ok {
		t.Fatal("a deactivated inbound webhook was filtered out; that is FindByEvent's rule, not this one's")
	}
	if got.JSScript == "" || fmt.Sprint(got.AllowedActions) != fmt.Sprint([]string{"user.create"}) {
		t.Fatalf("the inbound fields did not round-trip: %+v", got)
	}

	// An empty provider never matches: every outgoing-only configuration leaves
	// the field unset, so matching on "" would hand the router one of those.
	addWebhook(t, store, auth.WebhookConfig{URL: "https://out.example.test", Events: []string{"*"}})
	if _, ok, err = store.FindByProvider(ctx, ""); err != nil {
		t.Fatalf("find by empty provider: %v", err)
	} else if ok {
		t.Fatal("an empty provider matched an outgoing-only subscription")
	}
	if _, ok, err = store.FindByProvider(ctx, "nosuch"); err != nil {
		t.Fatalf("find by unknown provider: %v", err)
	} else if ok {
		t.Fatal("an unknown provider matched")
	}
}

func mustGetWebhook(t *testing.T, store *Store, id string) auth.WebhookConfig {
	t.Helper()
	page, err := store.ListWebhooks(context.Background(), webhookDirectoryCap, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, c := range page {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("webhook %s not found", id)
	return auth.WebhookConfig{}
}
