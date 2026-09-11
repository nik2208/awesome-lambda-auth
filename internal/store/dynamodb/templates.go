package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// This file implements auth.TemplateStore (template_store.go): the reference's
// ITemplateStore, through which a deployment overrides the built-in mail
// templates at run time and keeps one translation set per UI page. Both halves
// live in the TEMPLATES directory partition (data-model.md §1.6) — one item per
// template at MAIL#<id>, one per page at UI#<page> — with no GSI and no TTL.
//
// The semantics reproduced here are MemoryTemplateStore's, read from source
// rather than from the interface's doc comment, because the one place the two
// could be confused is the one that matters: MailTemplatePatch.Translations is
// the reference's Partial<MailTemplate> spread over the stored value
// (memory-template.store.ts:22), so a non-nil map REPLACES the whole
// lang → key → value map — languages it does not name are dropped, not merged.
// A caller that wants to change one language reads the template and sends the
// map back whole.

// Attribute names of the two template item types (data-model.md §5). The bodies
// follow the omission rule — an empty body is an absent attribute — and
// translations is always present, because the core always encodes it as {} and
// never as null (template_store.go, copyTranslations), so a raw item reads the
// way the reference's JSON does.
const (
	attrBaseHTML     = "baseHtml"
	attrBaseText     = "baseText"
	attrTranslations = "translations"
)

// MaxTemplateBytes caps a template item as itemBytes accounts for it. DynamoDB's
// own limit is 400 KB per item, and a template body is the one caller-supplied
// value in this table with no natural bound; refusing at 300 KB, on the merged
// item, turns the SDK's opaque ValidationException into ErrTemplateTooLarge
// before anything is written. The 100 KB margin is what lets the estimate be
// an estimate rather than a reimplementation of DynamoDB's accounting.
const MaxTemplateBytes = 300 * 1024

// templateDirectoryCap bounds the two list methods, whose interface has no
// cursor (data-model.md §8.6). The directory holds the six reference ids, the
// deployment's own, and one entry per UI page — dozens, not thousands — so the
// cap is an integrity check rather than a page size, and exceeding it is
// ErrResultTooLarge rather than a silent truncation.
const templateDirectoryCap = 1000

// templatePatchAttempts bounds the compare-and-set loop in UpdateMailTemplate.
//
// A patch loses its condition only because another writer's patch landed
// between this one's observation and its write, and every writer lands exactly
// once and leaves, so a writer loses at most once per concurrent writer: sixteen
// attempts guarantee that sixteen concurrent admins all land, with no sleep
// between attempts — the retry starts from the pre-image the failure returned,
// and waiting would only make that observation staler. Reaching the bound is
// therefore not contention but a fault (a token that cannot advance, a
// condition that cannot pass), and the bound is what turns it into
// ErrTemplateConflict instead of a spin.
const templatePatchAttempts = 16

var (
	// ErrTemplateTooLarge means the template as it would be stored — what the
	// patch keeps plus what it sets — exceeds MaxTemplateBytes. Nothing was
	// written; the stored template, if any, is as it was.
	ErrTemplateTooLarge = errors.New("dynamodb: template exceeds the item size limit")

	// ErrTemplateConflict means UpdateMailTemplate lost its compare-and-set
	// templatePatchAttempts times in a row. It is a fault rather than an
	// outcome — see templatePatchAttempts — and is preferred to answering it
	// with a patch that silently overwrote someone else's.
	ErrTemplateConflict = errors.New("dynamodb: template was patched concurrently too many times")

	// ErrInvalidTranslation means a locale or a translation key is the empty
	// string, which DynamoDB cannot store as a map key. MemoryTemplateStore
	// accepts one, but that is an accident of Go maps rather than a semantic
	// — nothing in the core or the reference produces or resolves an empty
	// locale — so it is refused at the boundary instead of failing inside the
	// SDK.
	ErrInvalidTranslation = errors.New("dynamodb: invalid translation")
)

// Templates returns this store as the auth.TemplateStore the composition root
// hands to auth.WithTemplateStore. The methods are on *Store itself
// (interfaces.go); the accessor exists so cmd/auth can find the capability
// structurally, the way it finds LinkedAccounts() and PendingLinks(), without
// importing this package's types into its own vocabulary.
func (s *Store) Templates() auth.TemplateStore { return s }

// GetMailTemplate resolves one template. A strongly-consistent read: an admin
// who has just saved a template must see it in the next mail the service sends,
// and an eventually-consistent read here would make that a race.
//
// An id the store cannot key — empty, over 64 bytes, or containing '#' — is an
// id it does not hold, and the answer is the reference's null rather than an
// error (cf. PendingLinks.Get): a lookup for a malformed id would otherwise be
// a 500 where a lookup for an unknown one is a 404.
func (s *Store) GetMailTemplate(ctx context.Context, id string) (auth.MailTemplate, bool, error) {
	if checkID("template id", id) != nil {
		return auth.MailTemplate{}, false, nil
	}
	m, err := s.getTemplateItem(ctx, mailTemplateSK(id), "get mail template")
	if err != nil || m == nil {
		return auth.MailTemplate{}, false, err
	}
	tpl, err := mailTemplateFromItem(m)
	if err != nil {
		return auth.MailTemplate{}, false, err
	}
	return tpl, true, nil
}

// ListMailTemplates returns every stored template, sorted by id. That is the
// order a Query returns the partition in, and it differs from
// MemoryTemplateStore's first-insertion order; the difference reaches the wire
// through the admin list route and is registered in CompatibilityNotes.
//
// An empty directory is an empty slice, never nil, so the list encodes as [] the
// way the memory store's does.
func (s *Store) ListMailTemplates(ctx context.Context) ([]auth.MailTemplate, error) {
	items, err := s.listTemplateItems(ctx, skMailTemplatePrefix, "list mail templates")
	if err != nil {
		return nil, err
	}
	out := make([]auth.MailTemplate, 0, len(items))
	for _, m := range items {
		tpl, err := mailTemplateFromItem(m)
		if err != nil {
			return nil, err
		}
		out = append(out, tpl)
	}
	return out, nil
}

// UpdateMailTemplate upserts: a template the store does not hold starts as
// {id, "", "", {}} (memory-template.store.ts:16-21) and the patch is spread on
// top, as applyMailTemplatePatch describes. The stored result is returned.
//
// This is a read-modify-write, and the read decides nothing. The fields the
// patch does not name have to come from somewhere, and the interface does not
// carry them; what makes the read safe is that the write re-asserts it — the
// PutItem is conditional on updatedAt still being the value observed (or on no
// token existing, when nothing was there), so two admins patching different
// fields of one template both land whichever order they arrive in, and a patch
// whose observation went stale is retried from the pre-image the failed
// condition returns rather than applied over the top of what it never saw.
// Same shape as LinkedAccounts.Save and ApplyEmailChange (data-model.md §1.3
// #22): the one read-then-write pattern this store allows is the one whose
// condition makes the read irrelevant to the outcome.
//
// The size check is on the merged item, before the write: a patch that fits on
// its own but not on top of what is stored is refused with ErrTemplateTooLarge
// and the stored template is untouched.
func (s *Store) UpdateMailTemplate(ctx context.Context, id string, patch auth.MailTemplatePatch) (auth.MailTemplate, error) {
	if err := checkID("template id", id); err != nil {
		return auth.MailTemplate{}, err
	}
	if err := checkTranslations(patch.Translations); err != nil {
		return auth.MailTemplate{}, err
	}

	sk := mailTemplateSK(id)
	current, err := s.getTemplateItem(ctx, sk, "get mail template")
	if err != nil {
		return auth.MailTemplate{}, err
	}
	for attempt := 0; ; attempt++ {
		tpl, observed, err := mailTemplateBase(current, id)
		if err != nil {
			return auth.MailTemplate{}, err
		}
		applyMailTemplatePatch(&tpl, patch)
		it := mailTemplateItem(tpl, s.nextStamp(observed))
		if n := itemBytes(it); n > MaxTemplateBytes {
			return auth.MailTemplate{}, fmt.Errorf("%w: %q would be %d bytes, limit %d", ErrTemplateTooLarge, id, n, MaxTemplateBytes)
		}

		err = s.putTemplateItem(ctx, it, observed)
		if err == nil {
			return tpl, nil
		}
		pre, lost := conditionFailedItem(err)
		if !lost {
			return auth.MailTemplate{}, wrap("update mail template", err)
		}
		if attempt == templatePatchAttempts-1 {
			return auth.MailTemplate{}, fmt.Errorf("%w: %q", ErrTemplateConflict, id)
		}
		current = pre
		if len(current) == 0 {
			// No pre-image. Either the item is gone — nothing here deletes one,
			// but an operator can — or the endpoint did not honour ALL_OLD on the
			// failed condition. A read tells the two apart; assuming absence
			// would loop against an item that exists.
			if current, err = s.getTemplateItem(ctx, sk, "get mail template"); err != nil {
				return auth.MailTemplate{}, err
			}
		}
	}
}

// GetUITranslations resolves one page's translation set. The same read, and the
// same answer for a page the store cannot key, as GetMailTemplate.
func (s *Store) GetUITranslations(ctx context.Context, page string) (auth.UITranslation, bool, error) {
	if checkID("ui page", page) != nil {
		return auth.UITranslation{}, false, nil
	}
	m, err := s.getTemplateItem(ctx, uiTranslationSK(page), "get ui translations")
	if err != nil || m == nil {
		return auth.UITranslation{}, false, err
	}
	ui, err := uiTranslationFromItem(m)
	if err != nil {
		return auth.UITranslation{}, false, err
	}
	return ui, true, nil
}

// ListUITranslations returns every stored page, sorted by page; see
// ListMailTemplates for the ordering and the empty case.
func (s *Store) ListUITranslations(ctx context.Context) ([]auth.UITranslation, error) {
	items, err := s.listTemplateItems(ctx, skUITranslationPrefix, "list ui translations")
	if err != nil {
		return nil, err
	}
	out := make([]auth.UITranslation, 0, len(items))
	for _, m := range items {
		ui, err := uiTranslationFromItem(m)
		if err != nil {
			return nil, err
		}
		out = append(out, ui)
	}
	return out, nil
}

// UpdateUITranslations replaces the page's translations wholesale
// (memory-template.store.ts:33-35): a page is set, not patched.
//
// Unconditional, because there is nothing to protect. UpdateMailTemplate's
// condition re-asserts an observation; this method makes none — nothing stored
// survives the call — so last-writer-wins is not a race but the semantics, and
// exactly what the memory store does under its lock.
func (s *Store) UpdateUITranslations(ctx context.Context, page string, translations map[string]map[string]string) (auth.UITranslation, error) {
	if err := checkID("ui page", page); err != nil {
		return auth.UITranslation{}, err
	}
	if err := checkTranslations(translations); err != nil {
		return auth.UITranslation{}, err
	}
	ui := auth.UITranslation{Page: page, Translations: copyTranslations(translations)}
	it := uiTranslationItem(ui, formatTime(s.nowUTC()))
	if n := itemBytes(it); n > MaxTemplateBytes {
		return auth.UITranslation{}, fmt.Errorf("%w: page %q would be %d bytes, limit %d", ErrTemplateTooLarge, page, n, MaxTemplateBytes)
	}
	if _, err := s.api.PutItem(ctx, &awsddb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      it,
	}); err != nil {
		return auth.UITranslation{}, wrap("update ui translations", err)
	}
	return ui, nil
}

// getTemplateItem reads one directory entry, strongly consistent. nil means
// absent.
func (s *Store) getTemplateItem(ctx context.Context, sk, op string) (map[string]types.AttributeValue, error) {
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(templatesPK, sk),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, wrap(op, err)
	}
	if len(out.Item) == 0 {
		return nil, nil
	}
	return out.Item, nil
}

// listTemplateItems drains one namespace of the directory. Strongly consistent
// for the same reason the point reads are: the admin who just saved is the one
// about to list.
func (s *Store) listTemplateItems(ctx context.Context, prefix, op string) ([]map[string]types.AttributeValue, error) {
	items, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		KeyConditionExpression:   aws.String("#PK = :pk AND begins_with(#SK, :prefix)"),
		ExpressionAttributeNames: exprNames(attrPK, attrSK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":     avS(templatesPK),
			":prefix": avS(prefix),
		},
		ConsistentRead: aws.Bool(true),
	}, templateDirectoryCap)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap(op, err)
	}
	return items, nil
}

// putTemplateItem is the conditional write behind UpdateMailTemplate. With no
// token observed the condition is that none exists — which is also true of an
// absent item, so create and "an item somebody wrote by hand without a token"
// are one case; with one observed, it must still be the one. ALL_OLD on failure
// is what lets the caller retry from the current item without a second read.
func (s *Store) putTemplateItem(ctx context.Context, it item, observed string) error {
	in := &awsddb.PutItemInput{
		TableName:                           aws.String(s.table),
		Item:                                it,
		ConditionExpression:                 aws.String("attribute_not_exists(#updatedAt)"),
		ExpressionAttributeNames:            exprNames(attrUpdatedAt),
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	}
	if observed != "" {
		in.ConditionExpression = aws.String("#updatedAt = :observed")
		in.ExpressionAttributeValues = map[string]types.AttributeValue{":observed": avS(observed)}
	}
	_, err := s.api.PutItem(ctx, in)
	return err
}

// nextStamp is the lock token a successful patch writes. It is the clock,
// unless the clock has not moved past the token observed — a pinned test clock,
// a coarse one, or a wall clock lagging the previous writer's — in which case it
// is one nanosecond past that token. The condition compares tokens for equality,
// so a token that failed to change would let the next stale patch through, and
// that is the one thing the token exists to prevent.
func (s *Store) nextStamp(observed string) string {
	stamp := formatTime(s.nowUTC())
	if stamp > observed {
		return stamp
	}
	last, err := parseTime(observed)
	if err != nil {
		// Not a timestamp at all, so it cannot equal one; the clock's value is
		// already distinct from it.
		return stamp
	}
	return formatTime(last.Add(time.Nanosecond))
}

// mailTemplateBase is what a patch is applied to: the stored template, or the
// empty one the core starts from, plus the lock token — the stored updatedAt,
// or "" when nothing is stored.
func mailTemplateBase(m map[string]types.AttributeValue, id string) (auth.MailTemplate, string, error) {
	if len(m) == 0 {
		return auth.MailTemplate{ID: id, Translations: map[string]map[string]string{}}, "", nil
	}
	tpl, err := mailTemplateFromItem(m)
	if err != nil {
		return auth.MailTemplate{}, "", err
	}
	return tpl, getS(m, attrUpdatedAt), nil
}

// applyMailTemplatePatch is the reference's shallow spread, {...existing,
// ...template} (memory-template.store.ts:22), exactly as
// MemoryTemplateStore.UpdateMailTemplate applies it: a nil body keeps the stored
// one, a pointer to "" clears it, and a non-nil translations map replaces the
// whole lang → key → value map. The replacement is a copy, so the returned
// template does not alias the caller's patch.
func applyMailTemplatePatch(tpl *auth.MailTemplate, patch auth.MailTemplatePatch) {
	if patch.BaseHTML != nil {
		tpl.BaseHTML = *patch.BaseHTML
	}
	if patch.BaseText != nil {
		tpl.BaseText = *patch.BaseText
	}
	if patch.Translations != nil {
		tpl.Translations = copyTranslations(patch.Translations)
	}
}

// checkTranslations refuses the one shape DynamoDB cannot store: an empty map
// key, at either level. Everything else about a locale or a key is opaque here.
func checkTranslations(translations map[string]map[string]string) error {
	for lang, values := range translations {
		if lang == "" {
			return fmt.Errorf("%w: empty locale", ErrInvalidTranslation)
		}
		for k := range values {
			if k == "" {
				return fmt.Errorf("%w: empty key under locale %q", ErrInvalidTranslation, lang)
			}
		}
	}
	return nil
}

// copyTranslations mirrors the core's (template_store.go): a nil input yields
// an empty map rather than nil, and a nil language is dropped rather than kept
// as an empty one.
func copyTranslations(in map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(in))
	for lang, values := range in {
		if values == nil {
			continue
		}
		out[lang] = maps.Clone(values)
	}
	return out
}

// translationsAV encodes lang → key → value as a map of maps of strings. An
// empty value is written as an empty S, which DynamoDB accepts for a non-key
// attribute; a nil language is omitted, as copyTranslations omits it.
func translationsAV(in map[string]map[string]string) types.AttributeValue {
	out := make(map[string]types.AttributeValue, len(in))
	for lang, values := range in {
		if values == nil {
			continue
		}
		m := make(map[string]types.AttributeValue, len(values))
		for k, v := range values {
			m[k] = &types.AttributeValueMemberS{Value: v}
		}
		out[lang] = &types.AttributeValueMemberM{Value: m}
	}
	return &types.AttributeValueMemberM{Value: out}
}

// translationsFromAV is the inverse. The result is never nil — an absent or
// malformed attribute reads as {} — and a value of an unexpected type is
// skipped rather than refused, which is §7's rule that readers tolerate what
// they do not understand.
func translationsFromAV(av types.AttributeValue) map[string]map[string]string {
	out := map[string]map[string]string{}
	m, ok := av.(*types.AttributeValueMemberM)
	if !ok {
		return out
	}
	for lang, lv := range m.Value {
		lm, ok := lv.(*types.AttributeValueMemberM)
		if !ok {
			continue
		}
		values := make(map[string]string, len(lm.Value))
		for k, kv := range lm.Value {
			if sv, ok := kv.(*types.AttributeValueMemberS); ok {
				values[k] = sv.Value
			}
		}
		out[lang] = values
	}
	return out
}

// mailTemplateItem encodes a template (data-model.md §5, "Mail template"). The
// id is not duplicated into an attribute: it is the tail of SK and nothing else
// reads it. updatedAt is the caller's lock token, not the clock, for the reason
// nextStamp gives.
func mailTemplateItem(tpl auth.MailTemplate, updatedAt string) item {
	return item{}.
		sAlways(attrPK, templatesPK).
		sAlways(attrSK, mailTemplateSK(tpl.ID)).
		stamp(typeMailTemplate).
		s(attrBaseHTML, tpl.BaseHTML).
		s(attrBaseText, tpl.BaseText).
		av(attrTranslations, translationsAV(tpl.Translations)).
		sAlways(attrUpdatedAt, updatedAt)
}

func mailTemplateFromItem(m map[string]types.AttributeValue) (auth.MailTemplate, error) {
	if err := checkVersion(m, typeMailTemplate); err != nil {
		return auth.MailTemplate{}, err
	}
	id, ok := mailTemplateIDFromSK(getS(m, attrSK))
	if !ok {
		return auth.MailTemplate{}, fmt.Errorf("dynamodb: %q is not a mail template sort key", getS(m, attrSK))
	}
	return auth.MailTemplate{
		ID:           id,
		BaseHTML:     getS(m, attrBaseHTML),
		BaseText:     getS(m, attrBaseText),
		Translations: translationsFromAV(m[attrTranslations]),
	}, nil
}

// uiTranslationItem encodes one page's set (data-model.md §5, "UI
// translations"); the page is the tail of SK.
func uiTranslationItem(ui auth.UITranslation, updatedAt string) item {
	return item{}.
		sAlways(attrPK, templatesPK).
		sAlways(attrSK, uiTranslationSK(ui.Page)).
		stamp(typeUITranslation).
		av(attrTranslations, translationsAV(ui.Translations)).
		sAlways(attrUpdatedAt, updatedAt)
}

func uiTranslationFromItem(m map[string]types.AttributeValue) (auth.UITranslation, error) {
	if err := checkVersion(m, typeUITranslation); err != nil {
		return auth.UITranslation{}, err
	}
	page, ok := uiTranslationPageFromSK(getS(m, attrSK))
	if !ok {
		return auth.UITranslation{}, fmt.Errorf("dynamodb: %q is not a ui translation sort key", getS(m, attrSK))
	}
	return auth.UITranslation{
		Page:         page,
		Translations: translationsFromAV(m[attrTranslations]),
	}, nil
}
