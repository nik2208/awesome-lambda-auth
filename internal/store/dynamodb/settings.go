package dynamodb

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// This file implements auth.SettingsStore (settings_store.go): the reference's
// ISettingsStore, the global switches an administrator flips through the admin
// Control panel at run time rather than at deploy time. It is one item — the
// deployment has one settings document, not one per tenant or per user — at
// PK=SETTINGS, SK=SETTINGS, with no GSI and no TTL (data-model.md §1.8).
//
// Two properties of the core's contract decide almost everything below, and both
// are subtler than they look.
//
// **nil is not the zero value; it is "absent", and absent means keep.**
// UpdateSettings applies MergeSettings, the reference's shallow spread
// (settings-store.interface.ts:20-24, :36-38): a field the patch does not carry
// is left untouched, a field it does carry replaces the stored one outright. So
// every field of AuthSettings is a pointer or a slice, and this store has to
// keep nil and zero apart on the way out as well as on the way in. That is why
// the encoding writes an absent field as an absent attribute rather than as
// false, "" or 0 — the omission rule of §5, here load-bearing for semantics and
// not merely for attribute_not_exists — and why the decoding uses pointer
// accessors of its own instead of getBool and getS.
//
// **The empty slice is a value, and it is the interesting one.**
// EnabledWebhookActions distinguishes nil (keep what is stored) from an empty
// non-nil slice (the administrator switching every inbound-webhook action off).
// The core has AuthSettings.MarshalJSON purely to keep that difference alive
// through an encoder, because `omitempty` on a []string drops an empty slice as
// well as a nil one and the cleared allowlist would come back as absent — which
// MergeSettings reads as keep, and the allowlist would quietly come back on.
// The same hole is open here and is closed the same way: nil omits the
// attribute, and a non-nil slice is written as an L, an empty one included.
// DynamoDB accepts an empty L for a non-key attribute, so nothing has to be
// invented to represent it.
//
// **UI is replaced whole, and that is the core's contract rather than a
// simplification.** A patch carrying a UI drops the seven branding fields it
// does not name (MergeSettings, and the reference's admin router merges the
// sub-object itself at admin.router.ts:979-981 precisely because the store does
// not). Nothing here merges it either: the stored M is overwritten by the patch's.
//
// The attribute names are the reference's JSON names, so a raw dump of this item
// reads as the document a node-auth deployment stores and a migration between
// the two is a copy.

// Attribute names of the settings item (data-model.md §5). They are the
// reference's key names verbatim (settings-store.interface.ts:45-92), including
// the capitalisation of require2FA, which is why they are written out rather
// than derived.
//
// require2FA is not among them: the name is already declared in users.go,
// because the user profile carries a per-user flag of the same name
// (models.go:23 versus settings-store.interface.ts:70), and the two really are
// the same spelling of the same word in the reference. They live on different
// item types and never in one item, so the constant is shared rather than
// duplicated — a second declaration of the same string is the thing that lets a
// codec and a condition drift apart, which is the argument users.go's comment
// already makes for keeping every attribute name in one place.
const (
	attrRequireEmailVerification = "requireEmailVerification"
	attrEmailVerificationMode    = "emailVerificationMode"
	attrLazyGraceDays            = "lazyEmailVerificationGracePeriodDays"
	attrEnabledWebhookActions    = "enabledWebhookActions"
	attrUI                       = "ui"
)

// uiSettingsAttrs maps each UISettings member to its attribute name and to the
// two halves of its codec, so the eight of them are one table rather than
// sixteen hand-written lines.
//
// That is the same constraint tokenFamily applies to the single-use tokens: the
// eight are identical but for a name, and a ninth added upstream is one row
// here. Writing them out would make the encode and the decode two lists that
// have to agree, and the failure mode of their disagreeing — a branding field
// that is written and never read back — is invisible until an admin saves a
// colour and it vanishes.
var uiSettingsAttrs = []struct {
	name string
	get  func(*auth.UISettings) *string
	set  func(*auth.UISettings, *string)
}{
	{"primaryColor", func(u *auth.UISettings) *string { return u.PrimaryColor }, func(u *auth.UISettings, v *string) { u.PrimaryColor = v }},
	{"secondaryColor", func(u *auth.UISettings) *string { return u.SecondaryColor }, func(u *auth.UISettings, v *string) { u.SecondaryColor = v }},
	{"logoUrl", func(u *auth.UISettings) *string { return u.LogoURL }, func(u *auth.UISettings, v *string) { u.LogoURL = v }},
	{"siteName", func(u *auth.UISettings) *string { return u.SiteName }, func(u *auth.UISettings, v *string) { u.SiteName = v }},
	{"logoPath", func(u *auth.UISettings) *string { return u.LogoPath }, func(u *auth.UISettings, v *string) { u.LogoPath = v }},
	{"bgColor", func(u *auth.UISettings) *string { return u.BgColor }, func(u *auth.UISettings, v *string) { u.BgColor = v }},
	{"bgImage", func(u *auth.UISettings) *string { return u.BgImage }, func(u *auth.UISettings, v *string) { u.BgImage = v }},
	{"cardBg", func(u *auth.UISettings) *string { return u.CardBg }, func(u *auth.UISettings, v *string) { u.CardBg = v }},
}

// MaxSettingsBytes caps the settings item as itemBytes accounts for it, for the
// same reason and with the same margin as MaxTemplateBytes: DynamoDB's own limit
// is 400 KB per item, refusing 100 KB under it is what lets the estimate be an
// estimate, and the point is that an operator gets a typed refusal naming the
// limit instead of the SDK's opaque ValidationException.
//
// Two of the fields here are caller-supplied and unbounded, which is why a
// singleton of half a dozen switches needs a cap at all: enabledWebhookActions is
// a list of action ids with no length limit anywhere in the interface, and the
// branding strings are URLs that nothing stops an admin from pasting a data: URI
// into. A stored document that cannot be written is a settings store that
// answers 500 to every read of require2FA, so the refusal has to happen before
// the write and on the merged document.
const MaxSettingsBytes = 300 * 1024

// settingsPatchAttempts bounds the compare-and-set loop in UpdateSettings.
//
// Sixteen, and the argument is templatePatchAttempts' argument: a patch loses
// its condition only because another writer's landed between this one's
// observation and its write, every writer lands exactly once and leaves, so a
// writer loses at most once per concurrent writer and sixteen attempts guarantee
// that sixteen concurrent admins all land — with no sleep between attempts,
// since the retry starts from the pre-image the failure returned and waiting
// would only make that observation staler.
//
// Contention here is lower than on a template by construction: there is one
// settings document per deployment, patched from an admin screen, so the writers
// are administrators and not requests. That makes reaching the bound even more
// clearly a fault than it is for a template — a token that cannot advance, a
// condition that cannot pass — which is what ErrSettingsConflict says instead of
// spinning.
const settingsPatchAttempts = 16

var (
	// ErrSettingsTooLarge means the settings as they would be stored — what the
	// patch keeps plus what it sets — exceed MaxSettingsBytes. Nothing was
	// written; the stored settings, if any, are as they were.
	ErrSettingsTooLarge = errors.New("dynamodb: settings exceed the item size limit")

	// ErrSettingsConflict means UpdateSettings lost its compare-and-set
	// settingsPatchAttempts times in a row. It is a fault rather than an
	// outcome — see settingsPatchAttempts — and is preferred to answering it
	// with a patch that silently overwrote another administrator's.
	ErrSettingsConflict = errors.New("dynamodb: settings were patched concurrently too many times")
)

// Settings returns this store as the auth.SettingsStore the composition root
// hands to auth.WithSettingsStore. The methods are on *Store itself
// (interfaces.go); the accessor exists so cmd/auth can find the capability
// structurally, the way it finds Templates() and AuthCodes(), without importing
// this package's types into its own vocabulary.
func (s *Store) Settings() auth.SettingsStore { return s }

// GetSettings reads the stored settings. Nothing stored is the zero
// AuthSettings and no error — the reference's empty object
// (settings-store.interface.ts:31-32) — and the error is reserved for the store
// itself failing, which is what fails /2fa/disable closed with a 500 rather than
// letting a require2FA of true read as absent.
//
// A strongly-consistent read, and not merely for tidiness: an administrator who
// has just switched require2FA on must not be able to reach /2fa/disable in the
// window before an eventually-consistent replica catches up, which is exactly
// the window an attacker holding a session would use.
func (s *Store) GetSettings(ctx context.Context) (auth.AuthSettings, error) {
	m, err := s.getSettingsItem(ctx)
	if err != nil || m == nil {
		return auth.AuthSettings{}, err
	}
	return settingsFromItem(m)
}

// UpdateSettings applies patch with auth.MergeSettings over what is stored and
// returns the result. An absent document starts as the zero AuthSettings, so the
// first write is an upsert and needs no separate create path.
//
// This is a read-modify-write, and the read decides nothing. The fields the
// patch does not carry have to come from somewhere and the interface does not
// supply them; what makes the read safe is that the write re-asserts it. The
// PutItem is conditional on updatedAt still being the value observed (or on no
// token existing, when nothing was there), so two administrators patching
// different keys both land whichever order they arrive in, and a patch whose
// observation went stale is retried from the pre-image the failed condition
// returns rather than applied over the top of what it never saw. Same shape,
// and the same shared primitive, as UpdateMailTemplate (putIfUnchanged in
// store.go; data-model.md §1.6 note 3 and §1.8).
//
// What that does *not* buy, and cannot: two administrators patching the ui block
// at the same time do not both survive. UI is one field of the patch and is
// replaced whole, so the second write wins the whole block — by the core's
// contract, not by this store's choice. The lock is about keys, exactly as the
// template lock is about fields.
//
// The size check is on the merged document, before the write: a patch that fits
// on its own but not on top of what is stored is refused with
// ErrSettingsTooLarge and the stored settings are untouched.
func (s *Store) UpdateSettings(ctx context.Context, patch auth.AuthSettings) (auth.AuthSettings, error) {
	current, err := s.getSettingsItem(ctx)
	if err != nil {
		return auth.AuthSettings{}, err
	}
	for attempt := 0; ; attempt++ {
		stored, observed, err := settingsBase(current)
		if err != nil {
			return auth.AuthSettings{}, err
		}
		merged := auth.MergeSettings(stored, patch)
		it := settingsItem(merged, s.nextStamp(observed))
		if n := itemBytes(it); n > MaxSettingsBytes {
			return auth.AuthSettings{}, fmt.Errorf("%w: the merged document would be %d bytes, limit %d", ErrSettingsTooLarge, n, MaxSettingsBytes)
		}

		err = s.putIfUnchanged(ctx, it, observed)
		if err == nil {
			return merged, nil
		}
		pre, lost := conditionFailedItem(err)
		if !lost {
			return auth.AuthSettings{}, wrap("update settings", err)
		}
		if attempt == settingsPatchAttempts-1 {
			return auth.AuthSettings{}, ErrSettingsConflict
		}
		current = pre
		if len(current) == 0 {
			// No pre-image. Either the item is gone — nothing here deletes one,
			// but an operator can — or the endpoint did not honour ALL_OLD on the
			// failed condition. A read tells the two apart; assuming absence
			// would loop against an item that exists.
			if current, err = s.getSettingsItem(ctx); err != nil {
				return auth.AuthSettings{}, err
			}
		}
	}
}

// getSettingsItem reads the singleton, strongly consistent. nil means absent.
func (s *Store) getSettingsItem(ctx context.Context) (map[string]types.AttributeValue, error) {
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(settingsPK, skSettings),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, wrap("get settings", err)
	}
	if len(out.Item) == 0 {
		return nil, nil
	}
	return out.Item, nil
}

// settingsBase is what a patch is applied to: the stored document, or the zero
// one, plus the lock token — the stored updatedAt, or "" when nothing is stored.
func settingsBase(m map[string]types.AttributeValue) (auth.AuthSettings, string, error) {
	if len(m) == 0 {
		return auth.AuthSettings{}, "", nil
	}
	stored, err := settingsFromItem(m)
	if err != nil {
		return auth.AuthSettings{}, "", err
	}
	return stored, getS(m, attrUpdatedAt), nil
}

// settingsItem encodes the document (data-model.md §5, "Runtime settings").
// Every field is written only when it is present, because absent is a value
// here — see the file header — and updatedAt is the caller's lock token, not the
// clock, for the reason nextStamp gives.
func settingsItem(s auth.AuthSettings, updatedAt string) item {
	it := item{}.
		sAlways(attrPK, settingsPK).
		sAlways(attrSK, skSettings).
		stamp(typeSettings)

	if s.RequireEmailVerification != nil {
		it = it.b(attrRequireEmailVerification, *s.RequireEmailVerification)
	}
	// sAlways rather than s: a pointer to "" is a value the administrator set,
	// and s would drop it, so it would read back as absent and MergeSettings
	// would keep whatever it replaced. The same applies to every UI member.
	if s.EmailVerificationMode != nil {
		it = it.sAlways(attrEmailVerificationMode, *s.EmailVerificationMode)
	}
	if s.LazyEmailVerificationGracePeriodDays != nil {
		it = it.n(attrLazyGraceDays, int64(*s.LazyEmailVerificationGracePeriodDays))
	}
	if s.Require2FA != nil {
		it = it.b(attrRequire2FA, *s.Require2FA)
	}
	if s.EnabledWebhookActions != nil {
		it = it.av(attrEnabledWebhookActions, stringListAV(s.EnabledWebhookActions))
	}
	if s.UI != nil {
		it = it.av(attrUI, uiSettingsAV(s.UI))
	}
	return it.sAlways(attrUpdatedAt, updatedAt)
}

func settingsFromItem(m map[string]types.AttributeValue) (auth.AuthSettings, error) {
	if err := checkVersion(m, typeSettings); err != nil {
		return auth.AuthSettings{}, err
	}
	return auth.AuthSettings{
		RequireEmailVerification:             getBoolPtr(m, attrRequireEmailVerification),
		EmailVerificationMode:                getStringPtr(m, attrEmailVerificationMode),
		LazyEmailVerificationGracePeriodDays: getIntPtr(m, attrLazyGraceDays),
		Require2FA:                           getBoolPtr(m, attrRequire2FA),
		EnabledWebhookActions:                stringListFromAV(m[attrEnabledWebhookActions]),
		UI:                                   uiSettingsFromAV(m[attrUI]),
	}, nil
}

// stringListAV encodes a []string as an L of S. An L rather than an SS for two
// reasons: DynamoDB forbids an empty SS, and the empty list is the value this
// field exists to be able to express (every inbound-webhook action switched
// off); and an SS is a set, so it would silently deduplicate and reorder a list
// the reference stores as a JSON array.
func stringListAV(in []string) types.AttributeValue {
	out := make([]types.AttributeValue, 0, len(in))
	for _, v := range in {
		out = append(out, avS(v))
	}
	return &types.AttributeValueMemberL{Value: out}
}

// stringListFromAV is the inverse, and it is where nil and empty are told apart:
// an absent or unreadable attribute is nil (absent, so MergeSettings keeps), and
// a present L is a non-nil slice even when it holds nothing.
//
// An element of an unexpected type is skipped rather than refused, which is §7's
// rule that readers tolerate what they do not understand.
func stringListFromAV(av types.AttributeValue) []string {
	l, ok := av.(*types.AttributeValueMemberL)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(l.Value))
	for _, e := range l.Value {
		if s, ok := e.(*types.AttributeValueMemberS); ok {
			out = append(out, s.Value)
		}
	}
	return out
}

// uiSettingsAV encodes the branding block as an M holding only the members that
// are set. A non-nil UI with nothing set is an empty M, not an absent attribute:
// the difference is a patch that cleared every branding field from one that
// never mentioned branding, and MergeSettings acts on it.
func uiSettingsAV(ui *auth.UISettings) types.AttributeValue {
	m := make(map[string]types.AttributeValue, len(uiSettingsAttrs))
	for _, f := range uiSettingsAttrs {
		if v := f.get(ui); v != nil {
			m[f.name] = avS(*v)
		}
	}
	return &types.AttributeValueMemberM{Value: m}
}

// uiSettingsFromAV is the inverse; an absent or unreadable attribute is nil.
func uiSettingsFromAV(av types.AttributeValue) *auth.UISettings {
	m, ok := av.(*types.AttributeValueMemberM)
	if !ok {
		return nil
	}
	ui := &auth.UISettings{}
	for _, f := range uiSettingsAttrs {
		if s, ok := m.Value[f.name].(*types.AttributeValueMemberS); ok {
			v := s.Value
			f.set(ui, &v)
		}
	}
	return ui
}

// The three pointer accessors this file needs.
//
// They live here rather than beside getS and getBool in item.go because the
// distinction they exist for — absent is not false, not "" and not 0 — is this
// document's contract and no other item type in the table has it. Everywhere
// else an absent optional attribute really does mean the zero value, and a
// pointer accessor would be an invitation to reintroduce a nil check that has
// nothing to decide.

func getBoolPtr(m map[string]types.AttributeValue, name string) *bool {
	av, ok := m[name].(*types.AttributeValueMemberBOOL)
	if !ok {
		return nil
	}
	v := av.Value
	return &v
}

func getStringPtr(m map[string]types.AttributeValue, name string) *string {
	av, ok := m[name].(*types.AttributeValueMemberS)
	if !ok {
		return nil
	}
	v := av.Value
	return &v
}

// getIntPtr reads an N. An attribute of another type, or a number this build
// cannot hold in an int, reads as absent rather than as an error: §7 again, and
// the alternative is that one hand-edited attribute makes every read of
// require2FA fail.
func getIntPtr(m map[string]types.AttributeValue, name string) *int {
	if _, ok := m[name].(*types.AttributeValueMemberN); !ok {
		return nil
	}
	raw := getN(m, name)
	v := int(raw)
	if int64(v) != raw {
		return nil
	}
	return &v
}
