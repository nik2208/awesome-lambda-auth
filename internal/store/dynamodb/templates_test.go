package dynamodb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// The template store, against DynamoDB Local. The semantic cases mirror the
// core's own suite for MemoryTemplateStore (template_store_test.go) so that the
// two implementations are held to the same reading of the reference; what is
// added is what only this store has — the lock, the size cap, the key
// validation, and the raw shape of the item.

func strPtr(s string) *string { return &s }

// TestTemplateKeysAndTheCoreIds is pure: the six ids the core defines, and the
// deprecated underscore spellings the doc says it still accepts, must all pass
// the validation this store applies, or a deployment could never override them.
func TestTemplateKeysAndTheCoreIds(t *testing.T) {
	t.Parallel()
	for _, id := range []string{
		auth.TemplatePasswordReset, auth.TemplateMagicLink, auth.TemplateWelcome,
		auth.TemplateVerifyEmail, auth.TemplateEmailChanged, auth.TemplateInvitation,
		"password_reset", "magic_link", "verify_email", "email_changed",
	} {
		if err := checkID("template id", id); err != nil {
			t.Errorf("core template id %q is refused by the store: %v", id, err)
		}
	}

	if got := mailTemplateSK("welcome"); got != "MAIL#welcome" {
		t.Errorf("mailTemplateSK = %q", got)
	}
	if got := uiTranslationSK("login"); got != "UI#login" {
		t.Errorf("uiTranslationSK = %q", got)
	}
	if id, ok := mailTemplateIDFromSK(mailTemplateSK("welcome")); !ok || id != "welcome" {
		t.Errorf("mailTemplateIDFromSK round trip = %q, %v", id, ok)
	}
	if page, ok := uiTranslationPageFromSK(uiTranslationSK("login")); !ok || page != "login" {
		t.Errorf("uiTranslationPageFromSK round trip = %q, %v", page, ok)
	}
	// The two namespaces must not decode as each other.
	if _, ok := mailTemplateIDFromSK("UI#login"); ok {
		t.Error("a UI sort key decoded as a mail template id")
	}
	if _, ok := uiTranslationPageFromSK("MAIL#welcome"); ok {
		t.Error("a mail sort key decoded as a UI page")
	}

	// The accessor hands out the store itself: the capability is on *Store, not
	// on a view (interfaces.go).
	s := &Store{}
	if s.Templates() != auth.TemplateStore(s) {
		t.Error("Templates() does not return the store itself")
	}
}

// A missing template starts as {id, "", "", {}} and the patch is spread on top;
// the JSON shape is the reference's (the core's own test, verbatim in intent).
func TestMailTemplateUpsertsFromAnEmptyTemplate(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if _, ok, err := store.GetMailTemplate(ctx, auth.TemplateWelcome); err != nil || ok {
		t.Fatalf("empty store: ok=%v err=%v, want a clean miss", ok, err)
	}
	got, err := store.UpdateMailTemplate(ctx, auth.TemplateWelcome, auth.MailTemplatePatch{BaseHTML: strPtr("<p>{{T.hi}}</p>")})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(got); err != nil {
		t.Fatal(err)
	}
	const want = `{"id":"welcome","baseHtml":"<p>{{T.hi}}</p>","baseText":"","translations":{}}`
	if encoded := strings.TrimSpace(buf.String()); encoded != want {
		t.Errorf("stored = %s, want %s", encoded, want)
	}
	again, ok, err := store.GetMailTemplate(ctx, auth.TemplateWelcome)
	if err != nil || !ok {
		t.Fatalf("get after update: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(again, got) {
		t.Errorf("get = %+v, want what update returned %+v", again, got)
	}
}

func TestMailTemplateRoundTrip(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	patch := auth.MailTemplatePatch{
		BaseHTML: strPtr("<h1>{{T.subject}}</h1><a href=\"{{link}}\">{{T.cta}}</a>"),
		BaseText: strPtr("{{T.subject}}\n{{link}}"),
		Translations: map[string]map[string]string{
			"en": {"subject": "Reset your password", "cta": "Reset", "hint": ""},
			"it": {"subject": "Reimposta la password", "cta": "Reimposta"},
		},
	}
	returned, err := store.UpdateMailTemplate(ctx, auth.TemplatePasswordReset, patch)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	want := auth.MailTemplate{
		ID:           auth.TemplatePasswordReset,
		BaseHTML:     *patch.BaseHTML,
		BaseText:     *patch.BaseText,
		Translations: patch.Translations,
	}
	if !reflect.DeepEqual(returned, want) {
		t.Errorf("update returned %+v, want %+v", returned, want)
	}
	fetched, ok, err := store.GetMailTemplate(ctx, auth.TemplatePasswordReset)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(fetched, want) {
		t.Errorf("get = %+v, want %+v", fetched, want)
	}

	// Nothing handed out aliases the patch: mutating the caller's map after the
	// call must not reach the value the call returned (the core's "hands out
	// copies" property, on the one path where this store could break it).
	patch.Translations["en"]["subject"] = "mutated through the patch"
	if returned.Translations["en"]["subject"] != "Reset your password" {
		t.Error("the returned template aliases the patch's translations map")
	}

	// The UI half, same shape.
	ui, err := store.UpdateUITranslations(ctx, "login", map[string]map[string]string{
		"en": {"title": "Sign in", "hint": ""},
		"it": {"title": "Accedi"},
		"xx": nil, // a nil language is dropped, as copyTranslations drops it
	})
	if err != nil {
		t.Fatalf("update ui: %v", err)
	}
	wantUI := auth.UITranslation{Page: "login", Translations: map[string]map[string]string{
		"en": {"title": "Sign in", "hint": ""},
		"it": {"title": "Accedi"},
	}}
	if !reflect.DeepEqual(ui, wantUI) {
		t.Errorf("update ui returned %+v, want %+v", ui, wantUI)
	}
	gotUI, ok, err := store.GetUITranslations(ctx, "login")
	if err != nil || !ok {
		t.Fatalf("get ui: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(gotUI, wantUI) {
		t.Errorf("get ui = %+v, want %+v", gotUI, wantUI)
	}
}

// TestMailTemplatePatchSemantics is the core's table (template_store_test.go,
// TestMemoryTemplateStorePatchSemantics), run against this store: nil keeps, a
// pointer to "" clears, and translations replace the whole map — never merge.
func TestMailTemplatePatchSemantics(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	seed := func(t *testing.T, id string) {
		t.Helper()
		if _, err := store.UpdateMailTemplate(ctx, id, auth.MailTemplatePatch{
			BaseHTML: strPtr("<p>h</p>"), BaseText: strPtr("t"),
			Translations: map[string]map[string]string{"en": {"subject": "S"}, "it": {"subject": "O"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	get := func(t *testing.T, id string) auth.MailTemplate {
		t.Helper()
		tpl, ok, err := store.GetMailTemplate(ctx, id)
		if err != nil || !ok {
			t.Fatalf("get: ok=%v err=%v", ok, err)
		}
		return tpl
	}

	t.Run("nil fields keep the stored values", func(t *testing.T) {
		const id = "case-nil-keeps"
		seed(t, id)
		before := get(t, id)
		if _, err := store.UpdateMailTemplate(ctx, id, auth.MailTemplatePatch{}); err != nil {
			t.Fatal(err)
		}
		if after := get(t, id); !reflect.DeepEqual(after, before) {
			t.Errorf("an empty patch changed the template: %+v -> %+v", before, after)
		}
	})

	t.Run("a pointer to the empty string clears a body", func(t *testing.T) {
		const id = "case-clear-body"
		seed(t, id)
		if _, err := store.UpdateMailTemplate(ctx, id, auth.MailTemplatePatch{BaseHTML: strPtr("")}); err != nil {
			t.Fatal(err)
		}
		if got := get(t, id); got.BaseHTML != "" || got.BaseText != "t" {
			t.Errorf("bodies = %q / %q, want the HTML cleared and the text kept", got.BaseHTML, got.BaseText)
		}
	})

	t.Run("translations replace the whole map", func(t *testing.T) {
		const id = "case-replace-map"
		seed(t, id)
		if _, err := store.UpdateMailTemplate(ctx, id, auth.MailTemplatePatch{
			Translations: map[string]map[string]string{"fr": {"subject": "F"}},
		}); err != nil {
			t.Fatal(err)
		}
		want := map[string]map[string]string{"fr": {"subject": "F"}}
		if got := get(t, id); !reflect.DeepEqual(got.Translations, want) || got.BaseHTML != "<p>h</p>" {
			t.Errorf("after the patch: %+v, want translations %v and the bodies kept", got, want)
		}
	})

	t.Run("an empty translations map clears every language", func(t *testing.T) {
		const id = "case-clear-map"
		seed(t, id)
		if _, err := store.UpdateMailTemplate(ctx, id, auth.MailTemplatePatch{
			Translations: map[string]map[string]string{},
		}); err != nil {
			t.Fatal(err)
		}
		if got := get(t, id); len(got.Translations) != 0 || got.Translations == nil {
			t.Errorf("translations = %v, want an empty, non-nil map", got.Translations)
		}
	})

	t.Run("a nil language is dropped, an empty one is kept", func(t *testing.T) {
		const id = "case-nil-language"
		seed(t, id)
		if _, err := store.UpdateMailTemplate(ctx, id, auth.MailTemplatePatch{
			Translations: map[string]map[string]string{"de": nil, "es": {}},
		}); err != nil {
			t.Fatal(err)
		}
		want := map[string]map[string]string{"es": {}}
		if got := get(t, id); !reflect.DeepEqual(got.Translations, want) {
			t.Errorf("translations = %v, want %v", got.Translations, want)
		}
	})

	t.Run("a UI page is set, not patched", func(t *testing.T) {
		if _, err := store.UpdateUITranslations(ctx, "register", map[string]map[string]string{
			"en": {"title": "Create account"}, "it": {"title": "Crea account"},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.UpdateUITranslations(ctx, "register", map[string]map[string]string{
			"fr": {"title": "Créer un compte"},
		}); err != nil {
			t.Fatal(err)
		}
		got, ok, err := store.GetUITranslations(ctx, "register")
		if err != nil || !ok {
			t.Fatalf("get ui: ok=%v err=%v", ok, err)
		}
		want := map[string]map[string]string{"fr": {"title": "Créer un compte"}}
		if !reflect.DeepEqual(got.Translations, want) {
			t.Errorf("translations = %v, want the second set only: %v", got.Translations, want)
		}
		if _, err := store.UpdateUITranslations(ctx, "register", nil); err != nil {
			t.Fatal(err)
		}
		if got, _, _ := store.GetUITranslations(ctx, "register"); got.Translations == nil || len(got.Translations) != 0 {
			t.Errorf("after a nil set: %v, want an empty, non-nil map", got.Translations)
		}
	})
}

// A miss is (zero, false, nil) — the reference's null — for an id the store
// does not hold and for one it could not hold.
func TestTemplateMissingIsACleanMiss(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	for _, id := range []string{auth.TemplateInvitation, "never-written", "", "has#hash", strings.Repeat("x", 65)} {
		tpl, ok, err := store.GetMailTemplate(ctx, id)
		if err != nil || ok || !reflect.DeepEqual(tpl, auth.MailTemplate{}) {
			t.Errorf("GetMailTemplate(%q) = %+v, %v, %v; want zero, false, nil", id, tpl, ok, err)
		}
		ui, ok, err := store.GetUITranslations(ctx, id)
		if err != nil || ok || !reflect.DeepEqual(ui, auth.UITranslation{}) {
			t.Errorf("GetUITranslations(%q) = %+v, %v, %v; want zero, false, nil", id, ui, ok, err)
		}
	}
}

// Lists come back sorted by id and by page — the partition's sort-key order —
// where the memory store returns first-insertion order. Registered in
// CompatibilityNotes; pinned here so the note cannot drift from the behaviour.
// An empty list is [] rather than nil, and the two namespaces never leak into
// each other's list.
func TestTemplateListsAreSortedAndNeverNil(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	mail, err := store.ListMailTemplates(ctx)
	if err != nil {
		t.Fatalf("list on an empty directory: %v", err)
	}
	if mail == nil || len(mail) != 0 {
		t.Errorf("empty mail list = %#v, want an empty, non-nil slice", mail)
	}
	ui, err := store.ListUITranslations(ctx)
	if err != nil {
		t.Fatalf("list ui on an empty directory: %v", err)
	}
	if ui == nil || len(ui) != 0 {
		t.Errorf("empty ui list = %#v, want an empty, non-nil slice", ui)
	}

	// Written deliberately out of order, and one of them twice: an update must
	// not move an entry, and the order must be the ids', not the writes'.
	ids := []string{auth.TemplateWelcome, auth.TemplateInvitation, auth.TemplatePasswordReset}
	for _, id := range ids {
		if _, err := store.UpdateMailTemplate(ctx, id, auth.MailTemplatePatch{BaseText: strPtr(id)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.UpdateMailTemplate(ctx, auth.TemplateWelcome, auth.MailTemplatePatch{BaseHTML: strPtr("updated")}); err != nil {
		t.Fatal(err)
	}
	pages := []string{"register", "login", "forgot-password"}
	for _, page := range pages {
		if _, err := store.UpdateUITranslations(ctx, page, map[string]map[string]string{"en": {"x": page}}); err != nil {
			t.Fatal(err)
		}
	}

	mail, err = store.ListMailTemplates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var gotIDs []string
	for _, tpl := range mail {
		gotIDs = append(gotIDs, tpl.ID)
		if tpl.BaseText != tpl.ID {
			t.Errorf("listed %q carries baseText %q, want the value written for it", tpl.ID, tpl.BaseText)
		}
	}
	wantIDs := append([]string(nil), ids...)
	sort.Strings(wantIDs)
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Errorf("mail templates listed %v, want sorted %v (insertion order was %v)", gotIDs, wantIDs, ids)
	}

	ui, err = store.ListUITranslations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var gotPages []string
	for _, u := range ui {
		gotPages = append(gotPages, u.Page)
	}
	wantPages := append([]string(nil), pages...)
	sort.Strings(wantPages)
	if !reflect.DeepEqual(gotPages, wantPages) {
		t.Errorf("ui pages listed %v, want sorted %v (insertion order was %v)", gotPages, wantPages, pages)
	}
}

// The cap is on the item as it would be stored, not on the patch: two halves
// that fit alone are refused together, and the refusal leaves the stored
// template as it was. A template just under the cap lands, which is what proves
// the cap is where it says it is and not lower.
func TestTemplateOversizeIsRefused(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	over := strings.Repeat("x", MaxTemplateBytes+1)
	_, err := store.UpdateMailTemplate(ctx, auth.TemplateWelcome, auth.MailTemplatePatch{BaseHTML: &over})
	if !errors.Is(err, ErrTemplateTooLarge) {
		t.Fatalf("oversize body: err = %v, want ErrTemplateTooLarge", err)
	}
	mustNotExist(t, client, store.table, templatesPK, mailTemplateSK(auth.TemplateWelcome))

	half := strings.Repeat("y", MaxTemplateBytes*2/3)
	if _, err := store.UpdateMailTemplate(ctx, auth.TemplateInvitation, auth.MailTemplatePatch{BaseHTML: &half}); err != nil {
		t.Fatalf("a body of two thirds the cap must land: %v", err)
	}
	_, err = store.UpdateMailTemplate(ctx, auth.TemplateInvitation, auth.MailTemplatePatch{BaseText: &half})
	if !errors.Is(err, ErrTemplateTooLarge) {
		t.Fatalf("a second body that only overflows on top of the first: err = %v, want ErrTemplateTooLarge", err)
	}
	got, ok, err := store.GetMailTemplate(ctx, auth.TemplateInvitation)
	if err != nil || !ok {
		t.Fatalf("get after refusal: ok=%v err=%v", ok, err)
	}
	if got.BaseHTML != half || got.BaseText != "" {
		t.Errorf("a refused patch changed the stored template: html %d bytes, text %d bytes", len(got.BaseHTML), len(got.BaseText))
	}

	fits := strings.Repeat("z", MaxTemplateBytes-4096)
	if _, err := store.UpdateMailTemplate(ctx, auth.TemplateMagicLink, auth.MailTemplatePatch{BaseHTML: &fits}); err != nil {
		t.Fatalf("a template just under the cap must land, or the cap is not %d: %v", MaxTemplateBytes, err)
	}

	// The UI half: the cap counts the map, names and values alike.
	_, err = store.UpdateUITranslations(ctx, "login", map[string]map[string]string{"en": {"blob": over}})
	if !errors.Is(err, ErrTemplateTooLarge) {
		t.Fatalf("oversize ui set: err = %v, want ErrTemplateTooLarge", err)
	}
	mustNotExist(t, client, store.table, templatesPK, uiTranslationSK("login"))
}

// An id or page the store cannot key is refused on write with a typed error and
// writes nothing — in particular, nothing under a key the '#' would have forged.
// An empty locale or key is refused the same way.
func TestTemplateIdentifiersAreValidated(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	for _, id := range []string{"", "has#hash", "MAIL#welcome", "../welcome", " welcome", strings.Repeat("x", 65)} {
		if _, err := store.UpdateMailTemplate(ctx, id, auth.MailTemplatePatch{BaseText: strPtr("t")}); !errors.Is(err, ErrInvalidIdentifier) {
			t.Errorf("UpdateMailTemplate(%q): err = %v, want ErrInvalidIdentifier", id, err)
		}
		if _, err := store.UpdateUITranslations(ctx, id, map[string]map[string]string{"en": {"k": "v"}}); !errors.Is(err, ErrInvalidIdentifier) {
			t.Errorf("UpdateUITranslations(%q): err = %v, want ErrInvalidIdentifier", id, err)
		}
	}
	for _, bad := range []map[string]map[string]string{
		{"": {"subject": "S"}},
		{"en": {"": "S"}},
	} {
		if _, err := store.UpdateMailTemplate(ctx, auth.TemplateWelcome, auth.MailTemplatePatch{Translations: bad}); !errors.Is(err, ErrInvalidTranslation) {
			t.Errorf("UpdateMailTemplate with %v: err = %v, want ErrInvalidTranslation", bad, err)
		}
		if _, err := store.UpdateUITranslations(ctx, "login", bad); !errors.Is(err, ErrInvalidTranslation) {
			t.Errorf("UpdateUITranslations with %v: err = %v, want ErrInvalidTranslation", bad, err)
		}
	}

	// Nothing reached the directory: neither a forged key nor a half-written
	// entry for the refused translations.
	out, err := client.Query(ctx, &awsddb.QueryInput{
		TableName:                 aws.String(store.table),
		KeyConditionExpression:    aws.String("#PK = :pk"),
		ExpressionAttributeNames:  exprNames(attrPK),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(templatesPK)},
		ConsistentRead:            aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("raw query: %v", err)
	}
	if len(out.Items) != 0 {
		t.Errorf("the directory holds %d item(s) after nothing but refused writes: %v", len(out.Items), out.Items)
	}
}

// The lock token must change on every successful patch even when the clock does
// not, or a second patch made under a pinned clock would carry the same token
// as the first and a stale third one would be let through.
func TestTemplatePatchTokenAdvancesUnderAPinnedClock(t *testing.T) {
	t.Parallel()
	fixed := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	store, client := newStore(t, func(o *Options) { o.Now = func() time.Time { return fixed } })
	ctx := context.Background()

	if _, err := store.UpdateMailTemplate(ctx, auth.TemplateWelcome, auth.MailTemplatePatch{BaseHTML: strPtr("h")}); err != nil {
		t.Fatal(err)
	}
	first := getS(rawItem(t, client, store.table, templatesPK, mailTemplateSK(auth.TemplateWelcome)), attrUpdatedAt)
	if first != formatTime(fixed) {
		t.Fatalf("first token = %q, want the clock %q", first, formatTime(fixed))
	}
	if _, err := store.UpdateMailTemplate(ctx, auth.TemplateWelcome, auth.MailTemplatePatch{BaseText: strPtr("t")}); err != nil {
		t.Fatalf("second patch under a pinned clock: %v", err)
	}
	second := getS(rawItem(t, client, store.table, templatesPK, mailTemplateSK(auth.TemplateWelcome)), attrUpdatedAt)
	if !(second > first) {
		t.Fatalf("token did not advance under a pinned clock: %q then %q", first, second)
	}
	if second != formatTime(fixed.Add(time.Nanosecond)) {
		t.Errorf("second token = %q, want one nanosecond past the first", second)
	}
	got, _, err := store.GetMailTemplate(ctx, auth.TemplateWelcome)
	if err != nil || got.BaseHTML != "h" || got.BaseText != "t" {
		t.Errorf("after two patches: %+v, %v; want both to have landed", got, err)
	}
}

// countingAPI counts the calls UpdateMailTemplate makes, so the concurrency test
// can report how the retries were served — from the pre-image or from a re-read.
type countingAPI struct {
	API
	gets, puts atomic.Int32
}

func (c *countingAPI) GetItem(ctx context.Context, in *awsddb.GetItemInput, o ...func(*awsddb.Options)) (*awsddb.GetItemOutput, error) {
	c.gets.Add(1)
	return c.API.GetItem(ctx, in, o...)
}

func (c *countingAPI) PutItem(ctx context.Context, in *awsddb.PutItemInput, o ...func(*awsddb.Options)) (*awsddb.PutItemOutput, error) {
	c.puts.Add(1)
	return c.API.PutItem(ctx, in, o...)
}

// TestTemplateConcurrentFieldPatchesAllLand is what the optimistic lock buys.
// Sixteen writers patch one template at once — five or six of them each field:
// the HTML body, the text body, the translations — starting from an id that
// does not exist yet, so the create path races too. Every patch must land
// (no ErrTemplateConflict: a writer loses at most once per other writer, and
// the bound exceeds the writer count), and afterwards every field must hold a
// value one of its own writers wrote. A store that wrote the merged item
// unconditionally would leave at least one field clobbered back to what a
// slower writer had observed.
//
// Note what is *not* asserted: that two locales patched concurrently both
// survive. They cannot, by the core's own contract — a non-nil translations map
// replaces the whole map — and a test that expected otherwise would be asserting
// a merge the reference does not perform.
func TestTemplateConcurrentFieldPatchesAllLand(t *testing.T) {
	t.Parallel()
	base, client := newStore(t)
	api := &countingAPI{API: client}
	store, err := New(api, Options{TableName: base.table, Logger: base.log})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	const writers = 16
	const rounds = 3
	for round := 0; round < rounds; round++ {
		id := fmt.Sprintf("race-%d-%s", round, randomHex(3))
		errs := make([]error, writers)
		var wg sync.WaitGroup
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				var patch auth.MailTemplatePatch
				switch i % 3 {
				case 0:
					patch.BaseHTML = strPtr(fmt.Sprintf("<p>html %d</p>", i))
				case 1:
					patch.BaseText = strPtr(fmt.Sprintf("text %d", i))
				default:
					patch.Translations = map[string]map[string]string{
						fmt.Sprintf("l%d", i): {"subject": fmt.Sprintf("S%d", i)},
					}
				}
				_, errs[i] = store.UpdateMailTemplate(ctx, id, patch)
			}(i)
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d writer %d: %v", round, i, err)
			}
		}

		got, ok, err := store.GetMailTemplate(ctx, id)
		if err != nil || !ok {
			t.Fatalf("round %d get: ok=%v err=%v", round, ok, err)
		}
		if !strings.HasPrefix(got.BaseHTML, "<p>html ") {
			t.Errorf("round %d: baseHtml = %q, want a value one of its writers wrote", round, got.BaseHTML)
		}
		if !strings.HasPrefix(got.BaseText, "text ") {
			t.Errorf("round %d: baseText = %q, want a value one of its writers wrote", round, got.BaseText)
		}
		if len(got.Translations) != 1 {
			t.Errorf("round %d: translations = %v, want exactly the one locale a writer set", round, got.Translations)
		}
		for lang, values := range got.Translations {
			var n int
			if _, err := fmt.Sscanf(lang, "l%d", &n); err != nil || n%3 != 2 || values["subject"] != fmt.Sprintf("S%d", n) {
				t.Errorf("round %d: locale %q = %v is not what any writer wrote", round, lang, values)
			}
		}
	}
	t.Logf("%d patches over %d rounds: %d PutItem and %d GetItem calls "+
		"(one GetItem per patch means every retry was served from the ALL_OLD pre-image)",
		writers*rounds, rounds, api.puts.Load(), api.gets.Load())
}

// TestAdvTemplateItemCarriesExactlyTheDocumentedAttributes reads the items back
// raw and pins the attribute set of each type to the one data-model.md §5
// documents — no more (no duplicated id, no GSI keys, no ttl, no NULLs for
// cleared bodies) and no less (translations present even when empty, the token
// always there). The assertion is on the set, not on the codec that wrote it, so
// a helper that started writing an extra attribute cannot agree with itself.
func TestAdvTemplateItemCarriesExactlyTheDocumentedAttributes(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	if _, err := store.UpdateMailTemplate(ctx, auth.TemplateVerifyEmail, auth.MailTemplatePatch{
		BaseHTML:     strPtr("<p>{{link}}</p>"),
		BaseText:     strPtr("{{link}}"),
		Translations: map[string]map[string]string{"en": {"subject": "Verify", "empty": ""}},
	}); err != nil {
		t.Fatal(err)
	}
	m := rawItem(t, client, store.table, templatesPK, mailTemplateSK(auth.TemplateVerifyEmail))
	assertAttributeSet(t, "mail template", m,
		attrPK, attrSK, attrType, attrVer, attrBaseHTML, attrBaseText, attrTranslations, attrUpdatedAt)
	if got := getS(m, attrType); got != "template" {
		t.Errorf("_t = %q, want %q", got, "template")
	}
	if got := getN(m, attrVer); got != schemaVersion {
		t.Errorf("_v = %d, want %d", got, schemaVersion)
	}
	if _, err := time.Parse(tsLayout, getS(m, attrUpdatedAt)); err != nil {
		t.Errorf("updatedAt %q is not in the fixed-width layout: %v", getS(m, attrUpdatedAt), err)
	}
	// translations is M of M of S, and an empty value is an empty S, not absent.
	tr, ok := m[attrTranslations].(*types.AttributeValueMemberM)
	if !ok {
		t.Fatalf("translations is %T, want M", m[attrTranslations])
	}
	en, ok := tr.Value["en"].(*types.AttributeValueMemberM)
	if !ok {
		t.Fatalf("translations.en is %T, want M", tr.Value["en"])
	}
	for k, want := range map[string]string{"subject": "Verify", "empty": ""} {
		sv, ok := en.Value[k].(*types.AttributeValueMemberS)
		if !ok || sv.Value != want {
			t.Errorf("translations.en.%s = %#v, want S %q", k, en.Value[k], want)
		}
	}

	// Clearing a body removes the attribute — no NULL, no empty string — and
	// clearing every language leaves an empty M, never an absent attribute.
	if _, err := store.UpdateMailTemplate(ctx, auth.TemplateVerifyEmail, auth.MailTemplatePatch{
		BaseText:     strPtr(""),
		Translations: map[string]map[string]string{},
	}); err != nil {
		t.Fatal(err)
	}
	m = rawItem(t, client, store.table, templatesPK, mailTemplateSK(auth.TemplateVerifyEmail))
	assertAttributeSet(t, "mail template after clearing", m,
		attrPK, attrSK, attrType, attrVer, attrBaseHTML, attrTranslations, attrUpdatedAt)
	if tr, ok := m[attrTranslations].(*types.AttributeValueMemberM); !ok || len(tr.Value) != 0 {
		t.Errorf("translations after clearing = %#v, want an empty M", m[attrTranslations])
	}

	// The UI item.
	if _, err := store.UpdateUITranslations(ctx, "login", map[string]map[string]string{"en": {"title": "Sign in"}}); err != nil {
		t.Fatal(err)
	}
	m = rawItem(t, client, store.table, templatesPK, uiTranslationSK("login"))
	assertAttributeSet(t, "ui translations", m,
		attrPK, attrSK, attrType, attrVer, attrTranslations, attrUpdatedAt)
	if got := getS(m, attrType); got != "uitranslation" {
		t.Errorf("_t = %q, want %q", got, "uitranslation")
	}
}

func assertAttributeSet(t *testing.T, what string, m map[string]types.AttributeValue, want ...string) {
	t.Helper()
	got := make([]string, 0, len(m))
	for name := range m {
		got = append(got, name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s item carries attributes %v, want exactly %v", what, got, want)
	}
}
