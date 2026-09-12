package dynamodb

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// PendingLinks implements auth.PendingLinkStore (oauth.go:37-42): the OAuth
// stash, one item per entry at PLINK#<state> (data-model.md #56-#58).
//
// Like LinkedAccounts it is its own type rather than three more methods on
// *Store, because Save and Delete collide with LinkedAccountStore's — see the
// comment there.
type PendingLinks struct{ store *Store }

// The second of the two view-borne assertions; see LinkedAccounts' for why the
// view exists and what a drift here costs. See interfaces.go for the convention.
var _ auth.PendingLinkStore = (*PendingLinks)(nil)

// PendingLinks returns the auth.PendingLinkStore view of this store.
func (s *Store) PendingLinks() auth.PendingLinkStore { return &PendingLinks{store: s} }

// The two outcomes a lookup can have besides success. The messages are
// MemoryPendingLinks' verbatim (oauth_wire.go:876, :880) so nothing that
// surfaces err.Error() changes; the sentinels exist so port code can match with
// errors.Is, and so that "never existed" stays distinguishable from "was there
// and has expired" without a second read.
//
// The core does not currently draw that distinction — every caller maps any Get
// error onto one route-specific literal (oauth_wire.go:531, :690, :766) — which
// has one wire-visible consequence, recorded in CompatibilityNotes: an expired
// account-link token answers INVALID_LINK_TOKEN rather than LINK_TOKEN_EXPIRED,
// because this store refuses to hand back an entry whose deadline has passed and
// LinkVerify's own expiry branch (oauth_wire.go:770-775) is therefore never
// reached. Handing an expired credential to the caller so it can produce a nicer
// error code is not a trade this store makes: §4.5 requires every read of a
// TTL-bearing item to treat a late item as absent, because TTL deletion is
// best-effort and can lag by roughly 48 hours.
var (
	ErrPendingLinkNotFound = errors.New("auth: pending link not found")
	ErrPendingLinkExpired  = errors.New("auth: pending link expired")
)

// pendingLinkItem encodes one stash entry.
//
// Two expiry attributes, deliberately:
//
//   - expiresAt is *this store's* deadline, derived from the ttl argument exactly
//     as MemoryPendingLinks derives its own (oauth_wire.go:860-869). A
//     non-positive ttl means no deadline and the attribute is omitted, which is
//     also what the memory store means by a zero expiresAt. It is what the
//     consume condition and the TTL attribute are built from.
//   - metaExpiresAt round-trips OAuthPendingMeta.ExpiresAt, which is the
//     *caller's* value and documented as "lets a consumer enforce the deadline
//     itself rather than trusting the store to have honoured the ttl argument"
//     (oauth.go:55-57). Folding it into the store's own deadline would return a
//     value the caller never wrote, and the two genuinely differ when a caller
//     passes an ExpiresAt with ttl <= 0.
func (s *Store) pendingLinkItem(state string, meta auth.OAuthPendingMeta, ttl time.Duration) item {
	// One clock read for the whole item, so createdAt and the deadline cannot
	// disagree with each other by a scheduling delay (see Store.nowUTC).
	now := s.nowUTC()
	it := item{}.
		sAlways(attrPK, pendingLinkPK(state)).
		sAlways(attrSK, skPendingLink).
		stamp(typePendingLink).
		s(attrProvider, meta.Provider).
		s(attrRedirectURL, meta.RedirectURL).
		s(attrTenantID, meta.TenantID).
		s(attrUserID, meta.UserID).
		s(attrEmail, meta.Email).
		s(attrProviderID, meta.ProviderAccountID).
		t(attrMetaExpiresAt, meta.ExpiresAt).
		t(attrCreatedAt, now)
	if ttl > 0 {
		deadline := now.Add(ttl)
		it = it.t(attrExpiresAt, deadline).ttl(deadline)
	}
	return it
}

func pendingLinkFromItem(m map[string]types.AttributeValue) (auth.OAuthPendingMeta, error) {
	if err := checkVersion(m, typePendingLink); err != nil {
		return auth.OAuthPendingMeta{}, err
	}
	meta := auth.OAuthPendingMeta{
		Provider:          getS(m, attrProvider),
		RedirectURL:       getS(m, attrRedirectURL),
		TenantID:          getS(m, attrTenantID),
		UserID:            getS(m, attrUserID),
		Email:             getS(m, attrEmail),
		ProviderAccountID: getS(m, attrProviderID),
	}
	var err error
	if meta.ExpiresAt, err = getTime(m, attrMetaExpiresAt); err != nil {
		return auth.OAuthPendingMeta{}, err
	}
	return meta, nil
}

// Save writes or replaces a stash entry.
//
// Unconditional, because MemoryPendingLinks is (oauth_wire.go:860-869): every key
// the core writes is a fresh 16-byte nonce or a sha256 of a fresh 32-byte token,
// so "already there" is a collision rather than a constraint, and a
// conditional put would only turn an ordinary retry into a failure.
//
// Nothing about the entry is a credential the store can verify, so there is no
// tenant argument to key on and none is invented: the tenant travels *inside* the
// entry and is read back out of it, which is how a capability-keyed item stays
// tenant-safe (§3).
func (p *PendingLinks) Save(ctx context.Context, state string, meta auth.OAuthPendingMeta, ttl time.Duration) error {
	s := p.store
	if err := checkStateKey(state); err != nil {
		return err
	}
	_, err := s.api.PutItem(ctx, &awsddb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      s.pendingLinkItem(state, meta, ttl),
	})
	if err != nil {
		return wrap("save pending link", err)
	}
	return nil
}

// Get resolves a stash entry and, for the two single-use namespaces, consumes it
// in the same call.
//
// This is the same choice tokens.go makes and for the same reason. The core's
// linking flow is Get → mutate → Delete as three separate store calls
// (oauth_wire.go:765-805) with nothing atomic across them, and it *discards
// Delete's error* (`_ = wiring.PendingLinks.Delete(...)`), so a store that only
// made Delete conditional would prove one winner to nobody: two Lambdas racing on
// one account-link token would both pass the Get and both write a link. Making
// the Get itself the conditional write closes that — exactly one caller can
// satisfy attribute_exists(PK), the losers get ErrPendingLinkNotFound, and the
// Delete that follows is an idempotent no-op.
//
// The cost is the same fail-closed posture: if the step after this one fails, the
// token is burned and the user asks for another link. That is right for auth, and
// for the OAuth state nonce it is the entire point — the nonce exists so a state
// cannot be replayed (oauth_wire.go:481-484).
//
// The conflict-stash namespace is *not* consumed; see
// pendingLinkSingleUsePrefixes for why, and for what happens to a namespace this
// build has never heard of.
func (p *PendingLinks) Get(ctx context.Context, state string) (auth.OAuthPendingMeta, error) {
	s := p.store
	if err := checkStateKey(state); err != nil {
		// An empty or malformed state must not resolve to whatever such a key
		// happens to hold, and the caller-facing answer is the same either way.
		return auth.OAuthPendingMeta{}, ErrPendingLinkNotFound
	}
	if !pendingLinkIsSingleUse(state) {
		if !pendingLinkIsKnown(state) {
			// Not a refusal: an unknown namespace is read the way the reference reads
			// everything. It is reported because if it turns out to be a credential,
			// nothing else would ever say so.
			s.warnUnknownPendingLinkNamespace(state)
		}
		return p.read(ctx, state)
	}
	if !s.consumeOnRead {
		return p.read(ctx, state)
	}
	m, err := s.consumeItemOnce(ctx, pendingLinkPK(state), skPendingLink, attrExpiresAt,
		ErrPendingLinkNotFound, ErrPendingLinkExpired)
	if err != nil {
		return auth.OAuthPendingMeta{}, err
	}
	return pendingLinkFromItem(m)
}

// read is the non-consuming lookup: the conflict stash, and the parity escape
// hatch (Options.NonAtomicSingleUseTokens) for the single-use namespaces.
//
// The expiry is still enforced, in code rather than in a condition, because there
// is no write to hang a condition on. That is the §4.5 rule applied to a
// read-only path: TTL deletion is best-effort, so a late item must read as absent.
func (p *PendingLinks) read(ctx context.Context, state string) (auth.OAuthPendingMeta, error) {
	s := p.store
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(pendingLinkPK(state), skPendingLink),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.OAuthPendingMeta{}, wrap("get pending link", err)
	}
	if len(out.Item) == 0 {
		return auth.OAuthPendingMeta{}, ErrPendingLinkNotFound
	}
	deadline, err := getTime(out.Item, attrExpiresAt)
	if err != nil {
		return auth.OAuthPendingMeta{}, err
	}
	if !deadline.IsZero() && !deadline.After(s.nowUTC()) {
		// Left for TTL rather than deleted here. MemoryPendingLinks deletes on
		// this path (oauth_wire.go:878-881); the difference is invisible, because
		// a later Get answers not-found either way, and a read method that writes
		// is worth avoiding when nothing requires it.
		return auth.OAuthPendingMeta{}, ErrPendingLinkExpired
	}
	return pendingLinkFromItem(out.Item)
}

// Delete drops a stash entry. Unconditional and idempotent: MemoryPendingLinks
// deletes without looking (oauth_wire.go:885-889), the core ignores the error,
// and after a consuming Get there is nothing left to remove.
func (p *PendingLinks) Delete(ctx context.Context, state string) error {
	s := p.store
	if err := checkStateKey(state); err != nil {
		return err
	}
	_, err := s.api.DeleteItem(ctx, &awsddb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key:       key(pendingLinkPK(state), skPendingLink),
	})
	if err != nil {
		return wrap("delete pending link", err)
	}
	return nil
}
