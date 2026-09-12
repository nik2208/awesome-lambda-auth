package dynamodb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// The settings store, against DynamoDB Local. The semantic cases mirror the
// core's own suite for MemorySettingsStore so that the two implementations are
// held to the same reading of the reference; what is added is what only this
// store has — the lock, the size cap, and the raw shape of the item.
//
// The cases that matter most are the ones about *absence*, because absence is a
// value in this interface and not a default: a field a patch does not carry is
// kept, so a store that lost the difference between "not set" and "set to the
// zero value" would answer a different contract while looking correct in every
// round trip of a populated document.

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

// TestSettingsKeysAndTheSingleton is pure: the key space is a constant partition
// holding one item, and the accessor hands out the store itself.
func TestSettingsKeysAndTheSingleton(t *testing.T) {
	t.Parallel()

	if settingsPK != "SETTINGS" || skSettings != "SETTINGS" {
		t.Errorf("settings key is %s/%s, want SETTINGS/SETTINGS", settingsPK, skSettings)
	}
	// No caller-supplied segment means no separator, and therefore nothing to
	// validate: there is no identifier a caller could forge into another key.
	if strings.Contains(settingsPK, keySep) || strings.Contains(skSettings, keySep) {
		t.Error("the settings key carries a separator, so something is meant to be interpolated into it")
	}
	// It must not land inside the template directory, whose two list methods
	// query a whole partition and would hand a settings item to a caller
	// expecting a MailTemplate.
	if settingsPK == templatesPK {
		t.Error("the settings item shares the template directory partition")
	}

	s := &Store{}
	if s.Settings() != auth.SettingsStore(s) {
		t.Error("Settings() does not return the store itself")
	}
}

// An empty store answers the reference's empty object, not an error and not a
// document of zero values.
func TestSettingsEmptyStoreIsTheEmptyObject(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	got, err := store.GetSettings(ctx)
	if err != nil {
		t.Fatalf("get on an empty store: %v", err)
	}
	if !reflect.DeepEqual(got, auth.AuthSettings{}) {
		t.Errorf("get on an empty store = %+v, want the zero AuthSettings", got)
	}
	if encoded := encodeSettings(t, got); encoded != "{}" {
		t.Errorf("the empty document encodes as %s, want {}", encoded)
	}
}

// The shallow spread, key by key: a nil field keeps what is stored, a non-nil
// one replaces it, and ui is replaced whole.
func TestSettingsPatchSemantics(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	first, err := store.UpdateSettings(ctx, auth.AuthSettings{
		Require2FA:                           boolPtr(true),
		EmailVerificationMode:                strPtr("lazy"),
		LazyEmailVerificationGracePeriodDays: intPtr(14),
		EnabledWebhookActions:                []string{"user.created", "user.deleted"},
		UI: &auth.UISettings{
			PrimaryColor: strPtr("#101010"),
			SiteName:     strPtr("Example"),
		},
	})
	if err != nil {
		t.Fatalf("first update: %v", err)
	}
	if got := encodeSettings(t, first); got != `{"emailVerificationMode":"lazy","lazyEmailVerificationGracePeriodDays":14,"require2FA":true,"enabledWebhookActions":["user.created","user.deleted"],"ui":{"primaryColor":"#101010","siteName":"Example"}}` {
		t.Errorf("first update returned %s", got)
	}

	// A patch naming one key leaves every other key alone.
	second, err := store.UpdateSettings(ctx, auth.AuthSettings{Require2FA: boolPtr(false)})
	if err != nil {
		t.Fatalf("second update: %v", err)
	}
	if second.Require2FA == nil || *second.Require2FA {
		t.Errorf("require2FA = %v, want false", second.Require2FA)
	}
	if second.EmailVerificationMode == nil || *second.EmailVerificationMode != "lazy" {
		t.Errorf("emailVerificationMode = %v, want the stored \"lazy\"", second.EmailVerificationMode)
	}
	if second.LazyEmailVerificationGracePeriodDays == nil || *second.LazyEmailVerificationGracePeriodDays != 14 {
		t.Errorf("grace period = %v, want the stored 14", second.LazyEmailVerificationGracePeriodDays)
	}
	if !reflect.DeepEqual(second.EnabledWebhookActions, []string{"user.created", "user.deleted"}) {
		t.Errorf("enabledWebhookActions = %v, want the stored pair", second.EnabledWebhookActions)
	}

	// ui is one field of the patch, so a patch carrying it replaces the block
	// whole: the seven members it does not name are dropped, not merged. That is
	// MergeSettings' contract, and the reference depends on it (its admin PATCH
	// route merges the sub-object itself, admin.router.ts:979-981).
	third, err := store.UpdateSettings(ctx, auth.AuthSettings{
		UI: &auth.UISettings{BgColor: strPtr("#ffffff")},
	})
	if err != nil {
		t.Fatalf("third update: %v", err)
	}
	if third.UI == nil || third.UI.BgColor == nil || *third.UI.BgColor != "#ffffff" {
		t.Fatalf("ui = %+v, want the patch's bgColor", third.UI)
	}
	if third.UI.PrimaryColor != nil || third.UI.SiteName != nil {
		t.Errorf("ui = %+v, want the members the patch did not name dropped, not merged", third.UI)
	}

	// Read back: the store must answer exactly what the last update returned.
	fetched, err := store.GetSettings(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(fetched, third) {
		t.Errorf("get = %+v, want what update returned %+v", fetched, third)
	}

	// Nothing handed out aliases the patch.
	actions := []string{"only.this"}
	returned, err := store.UpdateSettings(ctx, auth.AuthSettings{EnabledWebhookActions: actions})
	if err != nil {
		t.Fatal(err)
	}
	actions[0] = "mutated through the patch"
	if returned.EnabledWebhookActions[0] != "only.this" {
		t.Error("the returned document aliases the patch's slice")
	}
}

// TestSettingsClearedWebhookAllowlistRoundTrips is the one the core's
// MarshalJSON exists for, checked at the other end of the wire.
//
// An empty non-nil EnabledWebhookActions is the administrator switching every
// inbound-webhook action off. A store that encoded it the way `omitempty` would
// — as absent — would have MergeSettings read the next patch's nil as "keep"
// against a document that no longer said anything, and the allowlist would
// quietly come back on.
func TestSettingsClearedWebhookAllowlistRoundTrips(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	if _, err := store.UpdateSettings(ctx, auth.AuthSettings{
		EnabledWebhookActions: []string{"user.created"},
	}); err != nil {
		t.Fatal(err)
	}
	cleared, err := store.UpdateSettings(ctx, auth.AuthSettings{EnabledWebhookActions: []string{}})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if cleared.EnabledWebhookActions == nil || len(cleared.EnabledWebhookActions) != 0 {
		t.Fatalf("update returned %#v, want a non-nil empty slice", cleared.EnabledWebhookActions)
	}

	got, err := store.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.EnabledWebhookActions == nil {
		t.Fatal("the cleared allowlist read back as absent, so the next nil patch would restore the old one")
	}
	if len(got.EnabledWebhookActions) != 0 {
		t.Errorf("the cleared allowlist read back as %v", got.EnabledWebhookActions)
	}
	if encoded := encodeSettings(t, got); encoded != `{"enabledWebhookActions":[]}` {
		t.Errorf("the cleared allowlist encodes as %s, want an explicit []", encoded)
	}

	// The attribute really is present and empty in the item, which is what the
	// round trip above depends on.
	m := rawItem(t, client, store.table, settingsPK, skSettings)
	l, ok := m[attrEnabledWebhookActions].(*types.AttributeValueMemberL)
	if !ok {
		t.Fatalf("enabledWebhookActions is %#v, want an empty L", m[attrEnabledWebhookActions])
	}
	if len(l.Value) != 0 {
		t.Errorf("enabledWebhookActions = %#v, want empty", l.Value)
	}

	// And a patch that does not mention it keeps it cleared.
	after, err := store.UpdateSettings(ctx, auth.AuthSettings{Require2FA: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	if after.EnabledWebhookActions == nil || len(after.EnabledWebhookActions) != 0 {
		t.Errorf("after an unrelated patch the allowlist is %#v, want it still cleared", after.EnabledWebhookActions)
	}
}

// A ui block that is present and empty is also a value — every branding field
// cleared — and must not read back as "no branding was ever set".
func TestSettingsEmptyUIBlockIsNotAbsence(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if _, err := store.UpdateSettings(ctx, auth.AuthSettings{
		UI: &auth.UISettings{SiteName: strPtr("Example")},
	}); err != nil {
		t.Fatal(err)
	}
	cleared, err := store.UpdateSettings(ctx, auth.AuthSettings{UI: &auth.UISettings{}})
	if err != nil {
		t.Fatalf("clear ui: %v", err)
	}
	if cleared.UI == nil {
		t.Fatal("clearing every branding member returned a nil ui block")
	}

	got, err := store.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.UI == nil {
		t.Fatal("the cleared ui block read back as absent, so the next nil patch would restore the old branding")
	}
	if !reflect.DeepEqual(got.UI, &auth.UISettings{}) {
		t.Errorf("the cleared ui block read back as %+v", got.UI)
	}
}

// Every UISettings member has to survive a round trip. The codec is a table and
// this is what holds the table to the struct: a member added upstream and
// forgotten here would be written by nothing and read as nil, so an admin who
// saved it would watch it vanish.
func TestSettingsUIMembersAllRoundTrip(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	full := &auth.UISettings{
		PrimaryColor:   strPtr("#111111"),
		SecondaryColor: strPtr("#222222"),
		LogoURL:        strPtr("https://cdn.example.test/logo.svg"),
		SiteName:       strPtr("Example"),
		LogoPath:       strPtr("/assets/logo.svg"),
		BgColor:        strPtr("#333333"),
		BgImage:        strPtr("https://cdn.example.test/bg.png"),
		CardBg:         strPtr(""), // an empty string is a value, not an absence
	}
	if _, err := store.UpdateSettings(ctx, auth.AuthSettings{UI: full}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.UI, full) {
		t.Errorf("ui round trip = %+v, want %+v", got.UI, full)
	}

	// The table itself must cover the struct. reflect is the only thing that can
	// say so, because a missing row is not a compile error.
	if n := reflect.TypeOf(auth.UISettings{}).NumField(); n != len(uiSettingsAttrs) {
		t.Errorf("auth.UISettings has %d fields and uiSettingsAttrs has %d rows; a member with no row is written by nothing",
			n, len(uiSettingsAttrs))
	}
}

// The size cap is measured on the merged document, before the write, so a patch
// that fits on its own but not on top of what is stored is refused and the
// stored settings are untouched.
func TestSettingsOversizeIsRefused(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	half := strings.Repeat("b", MaxSettingsBytes/2)
	if _, err := store.UpdateSettings(ctx, auth.AuthSettings{
		UI: &auth.UISettings{BgImage: strPtr(half)},
	}); err != nil {
		t.Fatalf("a document under the cap was refused: %v", err)
	}

	// On its own this patch fits; on top of what is stored it does not.
	_, err := store.UpdateSettings(ctx, auth.AuthSettings{
		EmailVerificationMode: strPtr(half),
	})
	if !errors.Is(err, ErrSettingsTooLarge) {
		t.Fatalf("oversize merge: %v, want ErrSettingsTooLarge", err)
	}

	// Nothing was written: the stored document is as it was.
	got, err := store.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.EmailVerificationMode != nil {
		t.Error("the refused patch was partly applied")
	}
	if got.UI == nil || got.UI.BgImage == nil || len(*got.UI.BgImage) != len(half) {
		t.Error("the refused patch disturbed the stored document")
	}
}

// The lock token has to advance even when the clock does not, or the next stale
// patch would satisfy a condition it should have lost.
func TestSettingsPatchTokenAdvancesUnderAPinnedClock(t *testing.T) {
	t.Parallel()
	fixed := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	store, client := newStore(t, func(o *Options) { o.Now = func() time.Time { return fixed } })
	ctx := context.Background()

	if _, err := store.UpdateSettings(ctx, auth.AuthSettings{Require2FA: boolPtr(true)}); err != nil {
		t.Fatal(err)
	}
	first := getS(rawItem(t, client, store.table, settingsPK, skSettings), attrUpdatedAt)
	if first != formatTime(fixed) {
		t.Fatalf("first token = %q, want the clock %q", first, formatTime(fixed))
	}
	if _, err := store.UpdateSettings(ctx, auth.AuthSettings{EmailVerificationMode: strPtr("strict")}); err != nil {
		t.Fatalf("second patch under a pinned clock: %v", err)
	}
	second := getS(rawItem(t, client, store.table, settingsPK, skSettings), attrUpdatedAt)
	if second != formatTime(fixed.Add(time.Nanosecond)) {
		t.Errorf("second token = %q, want one nanosecond past the first %q", second, first)
	}
	got, err := store.GetSettings(ctx)
	if err != nil || got.Require2FA == nil || !*got.Require2FA || got.EmailVerificationMode == nil {
		t.Errorf("after two patches: %+v, %v; want both to have landed", got, err)
	}
}

// TestSettingsConcurrentKeyPatchesAllLand is what the optimistic lock buys, and
// the guarantee UpdateMailTemplate makes for a template made here for the
// settings singleton: sixteen administrators patching at once all land.
//
// Two rounds, on purpose: the first races the create path, since the document
// does not exist when the writers start, and the second races the update path
// against the document the first left behind. A store that wrote the merged
// document unconditionally would pass neither — every key but the last writer's
// would be blanked back to what a slower writer had observed.
//
// Note what is *not* asserted: that two concurrent patches of the ui block both
// survive. They cannot, by the core's own contract — ui is replaced whole — and
// a test that expected otherwise would be asserting a merge the reference does
// not perform.
func TestSettingsConcurrentKeyPatchesAllLand(t *testing.T) {
	t.Parallel()
	base, client := newStore(t)
	api := &countingAPI{API: client}
	store, err := New(api, Options{TableName: base.table, Logger: base.log})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	const writers = 16
	for round := 0; round < 2; round++ {
		errs := make([]error, writers)
		var wg sync.WaitGroup
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				n := round*writers + i
				var patch auth.AuthSettings
				switch i % 6 {
				case 0:
					patch.Require2FA = boolPtr(true)
				case 1:
					patch.RequireEmailVerification = boolPtr(true)
				case 2:
					patch.EmailVerificationMode = strPtr(fmt.Sprintf("mode-%d", n))
				case 3:
					patch.LazyEmailVerificationGracePeriodDays = intPtr(n + 1)
				case 4:
					patch.EnabledWebhookActions = []string{fmt.Sprintf("action-%d", n)}
				default:
					patch.UI = &auth.UISettings{SiteName: strPtr(fmt.Sprintf("site-%d", n))}
				}
				_, errs[i] = store.UpdateSettings(ctx, patch)
			}(i)
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d writer %d: %v", round, i, err)
			}
		}

		got, err := store.GetSettings(ctx)
		if err != nil {
			t.Fatalf("round %d get: %v", round, err)
		}
		if got.Require2FA == nil || !*got.Require2FA {
			t.Errorf("round %d: require2FA = %v, want the value its writers wrote", round, got.Require2FA)
		}
		if got.RequireEmailVerification == nil || !*got.RequireEmailVerification {
			t.Errorf("round %d: requireEmailVerification = %v, want the value its writers wrote", round, got.RequireEmailVerification)
		}
		assertWrittenBySomeWriter(t, round, "emailVerificationMode", got.EmailVerificationMode, "mode-%d", writers, 2)
		if got.LazyEmailVerificationGracePeriodDays == nil {
			t.Errorf("round %d: the grace period was clobbered back to absent", round)
		} else if n := *got.LazyEmailVerificationGracePeriodDays - 1; (n%writers)%6 != 3 {
			t.Errorf("round %d: grace period = %d is not a value any writer wrote", round, *got.LazyEmailVerificationGracePeriodDays)
		}
		if len(got.EnabledWebhookActions) != 1 {
			t.Errorf("round %d: enabledWebhookActions = %v, want exactly the one entry a writer set", round, got.EnabledWebhookActions)
		} else {
			assertWrittenBySomeWriter(t, round, "enabledWebhookActions[0]", &got.EnabledWebhookActions[0], "action-%d", writers, 4)
		}
		if got.UI == nil || got.UI.SiteName == nil {
			t.Errorf("round %d: ui = %+v, want the block a writer set", round, got.UI)
		} else {
			assertWrittenBySomeWriter(t, round, "ui.siteName", got.UI.SiteName, "site-%d", writers, 5)
		}
	}
	t.Logf("%d patches over 2 rounds: %d PutItem and %d GetItem calls "+
		"(one GetItem per patch means every retry was served from the ALL_OLD pre-image)",
		writers*2, api.puts.Load(), api.gets.Load())
}

// assertWrittenBySomeWriter checks that a value came from one of the writers
// that owned its key, rather than from a clobbering merge.
//
// Each writer stamps its serial n = round*writers + i into the value it writes,
// so the writer's slot is recovered as (n mod writers) mod 6 — n alone would not
// do, because the second round's serials are offset and would name a different
// slot.
func assertWrittenBySomeWriter(t *testing.T, round int, what string, got *string, format string, writers, slot int) {
	t.Helper()
	if got == nil {
		t.Errorf("round %d: %s was clobbered back to absent", round, what)
		return
	}
	var n int
	if _, err := fmt.Sscanf(*got, format, &n); err != nil || (n%writers)%6 != slot {
		t.Errorf("round %d: %s = %q is not a value any of its writers wrote", round, what, *got)
	}
}

// TestAdvSettingsItemCarriesExactlyTheDocumentedAttributes reads the item back
// raw and pins its attribute set to the one data-model.md §5 documents — no more
// (no GSI keys, no ttl, no NULLs and no zero values for keys nobody set) and no
// less (the token always there). The assertion is on the set, not on the codec
// that wrote it, so a helper that started writing an extra attribute cannot
// agree with itself.
//
// The absent half is the point. Everywhere else in this table an omitted
// optional attribute is a tidiness rule; here it is the difference between "the
// administrator has not set this" and "the administrator set this to false",
// and a codec that wrote a zero value for an unset key would change what the
// next patch means.
func TestAdvSettingsItemCarriesExactlyTheDocumentedAttributes(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	if _, err := store.UpdateSettings(ctx, auth.AuthSettings{Require2FA: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	m := rawItem(t, client, store.table, settingsPK, skSettings)
	assertAttributeSet(t, "settings after one key", m,
		attrPK, attrSK, attrType, attrVer, attrRequire2FA, attrUpdatedAt)
	if got := getS(m, attrType); got != "settings" {
		t.Errorf("_t = %q, want %q", got, "settings")
	}
	if got := getN(m, attrVer); got != schemaVersion {
		t.Errorf("_v = %d, want %d", got, schemaVersion)
	}
	if _, err := time.Parse(tsLayout, getS(m, attrUpdatedAt)); err != nil {
		t.Errorf("updatedAt %q is not in the fixed-width layout: %v", getS(m, attrUpdatedAt), err)
	}
	if av, ok := m[attrRequire2FA].(*types.AttributeValueMemberBOOL); !ok || av.Value {
		t.Errorf("require2FA = %#v, want BOOL false", m[attrRequire2FA])
	}

	// Every key set: the full attribute set, and the two composite types.
	if _, err := store.UpdateSettings(ctx, auth.AuthSettings{
		RequireEmailVerification:             boolPtr(true),
		EmailVerificationMode:                strPtr("strict"),
		LazyEmailVerificationGracePeriodDays: intPtr(7),
		EnabledWebhookActions:                []string{"user.created"},
		UI:                                   &auth.UISettings{SiteName: strPtr("Example")},
	}); err != nil {
		t.Fatal(err)
	}
	m = rawItem(t, client, store.table, settingsPK, skSettings)
	assertAttributeSet(t, "settings with every key", m,
		attrPK, attrSK, attrType, attrVer,
		attrRequireEmailVerification, attrEmailVerificationMode, attrLazyGraceDays,
		attrRequire2FA, attrEnabledWebhookActions, attrUI, attrUpdatedAt)
	if l, ok := m[attrEnabledWebhookActions].(*types.AttributeValueMemberL); !ok || len(l.Value) != 1 {
		t.Errorf("enabledWebhookActions = %#v, want an L of one", m[attrEnabledWebhookActions])
	}
	ui, ok := m[attrUI].(*types.AttributeValueMemberM)
	if !ok {
		t.Fatalf("ui is %T, want M", m[attrUI])
	}
	// Only the member that was set: the branding block is not padded out with
	// the seven nobody named.
	if len(ui.Value) != 1 {
		t.Errorf("ui = %#v, want exactly the one member the patch set", ui.Value)
	}
	if s, ok := ui.Value["siteName"].(*types.AttributeValueMemberS); !ok || s.Value != "Example" {
		t.Errorf("ui.siteName = %#v", ui.Value["siteName"])
	}
	if got := getN(m, attrLazyGraceDays); got != 7 {
		t.Errorf("lazyEmailVerificationGracePeriodDays = %d, want 7", got)
	}
}

// TestSettingsToleratesAnItemFromAnotherWriter is §7 rule 2 for this item: an
// attribute this build does not know is ignored rather than refused, and an
// attribute of an unexpected type reads as absent rather than as a 500 on every
// read of require2FA.
func TestSettingsToleratesAnItemFromAnotherWriter(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	it := settingsItem(auth.AuthSettings{Require2FA: boolPtr(true)}, formatTime(store.nowUTC()))
	it["somethingNewer"] = avS("from a later build")
	it[attrLazyGraceDays] = avS("not a number")
	if _, err := client.PutItem(ctx, &awsddb.PutItemInput{TableName: &store.table, Item: it}); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetSettings(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Require2FA == nil || !*got.Require2FA {
		t.Errorf("require2FA = %v; an unknown attribute must not cost the keys this build does understand", got.Require2FA)
	}
	if got.LazyEmailVerificationGracePeriodDays != nil {
		t.Errorf("grace period = %v, want absent for an attribute of the wrong type", got.LazyEmailVerificationGracePeriodDays)
	}

	// A patch still lands on top of it, and does not carry the stranger forward
	// or lose it: the item is rewritten whole, so the unknown attribute goes.
	// That is the honest outcome of a whole-item PutItem and is why §7's promise
	// is to tolerate an unknown attribute on read, not to preserve it.
	if _, err := store.UpdateSettings(ctx, auth.AuthSettings{EmailVerificationMode: strPtr("lazy")}); err != nil {
		t.Fatalf("patch over a stranger's item: %v", err)
	}
	after, err := store.GetSettings(ctx)
	if err != nil || after.EmailVerificationMode == nil || *after.EmailVerificationMode != "lazy" {
		t.Errorf("after the patch: %+v, %v", after, err)
	}
	if after.Require2FA == nil || !*after.Require2FA {
		t.Errorf("the patch dropped a key it did not name: %+v", after)
	}
}

// A schema version from the future is refused rather than half-read, which is
// the one thing §7 does not promise forward compatibility for.
func TestSettingsFromANewerSchemaIsRefused(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	it := settingsItem(auth.AuthSettings{Require2FA: boolPtr(true)}, formatTime(store.nowUTC()))
	it[attrVer] = avN(schemaVersion + 1)
	if _, err := client.PutItem(ctx, &awsddb.PutItemInput{TableName: &store.table, Item: it}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSettings(ctx); err == nil {
		t.Error("a settings item from a newer schema was read without complaint")
	}
	if _, err := store.UpdateSettings(ctx, auth.AuthSettings{Require2FA: boolPtr(false)}); err == nil {
		t.Error("a settings item from a newer schema was patched without complaint")
	}
}

// encodeSettings renders a document the way the core's MarshalJSON does, which
// is the shape the admin surface will put on the wire.
func encodeSettings(t *testing.T, s auth.AuthSettings) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(buf.String())
}
