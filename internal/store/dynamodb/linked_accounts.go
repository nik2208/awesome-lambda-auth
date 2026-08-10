package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// LinkedAccounts implements auth.LinkedAccountStore (oauth.go:79-85) over the
// same table as the Store it comes from.
//
// It is a separate type, and not four more methods on *Store, because it has to
// be: auth.LinkedAccountStore and auth.PendingLinkStore both declare Save and
// Delete, and their Delete has the *same* signature — Delete(ctx, string) error
// — while meaning "drop this link id" in one and "drop this state key" in the
// other. One type cannot carry both, so each optional OAuth store gets its own
// view. That is also why these two are the only stores in this package the core
// does not discover by type assertion: they are handed to it explicitly, through
// auth.WithOAuth (oauth_wire.go:226-233).
type LinkedAccounts struct{ store *Store }

// LinkedAccounts returns the auth.LinkedAccountStore view of this store. The
// return type is the interface rather than the concrete type so that the
// composition root can find it structurally without importing this package's
// types into its own vocabulary.
func (s *Store) LinkedAccounts() auth.LinkedAccountStore { return &LinkedAccounts{store: s} }

// ErrLinkedAccountNotFound is returned by FindByProvider for a provider account
// nobody has linked. The message is MemoryLinkedAccounts' verbatim
// (oauth.go:409), so nothing that surfaces err.Error() changes; the sentinel
// exists so port code can match with errors.Is.
var ErrLinkedAccountNotFound = errors.New("auth: linked account not found")

// ErrLinkedAccountConflict means a binding was rewritten by somebody else while
// this Save was rebinding it, repeatedly. It is a fault rather than an outcome:
// two callers rebinding one provider account at the same moment is either a
// retry storm or a bug, and answering it with a lost link would be worse than
// answering it with an error.
var ErrLinkedAccountConflict = errors.New("dynamodb: linked account was rebound concurrently")

// linkRebindAttempts bounds the compare-and-set loop in Save. Rebinding is a
// human-scale event — an OAuth callback or a clicked verification link — so
// contention is theoretical; the loop exists so that losing a race once is not a
// failure, not because a hot path needs it.
const linkRebindAttempts = 4

// DefaultMaxLinkedAccountsPerUser caps ListForUser, whose interface has no cursor
// (data-model.md §8.6). A user with three digits of provider bindings is an
// incident to investigate, not a page to render, and a silent truncation would
// make GET /linked-accounts lie about which providers can sign this account in —
// the one thing that screen exists to say. So the store refuses instead.
const DefaultMaxLinkedAccountsPerUser = 100

// linkItem encodes the canonical linked-account item (data-model.md §2.2,
// "Linked account"). tenantId is deliberately absent: auth.OAuthLinkedAccount has
// no tenant field (oauth.go:68-77), every method of the interface lacks one, and
// inventing one would invent semantics. Isolation instead comes from the key
// being a capability — a provider account id nobody else's provider issues — and
// from the fact that resolving the link to a user goes through GetUserByID with a
// tenant the caller already holds (§3).
func linkItem(link auth.OAuthLinkedAccount) item {
	return item{}.
		sAlways(attrPK, oauthPK(link.Provider, link.ProviderID)).
		sAlways(attrSK, skOAuth).
		stamp(typeLink).
		sAlways(attrLinkID, link.ID).
		sAlways(attrUserID, link.UserID).
		sAlways(attrProvider, link.Provider).
		sAlways(attrProviderID, link.ProviderID).
		s(attrEmail, link.Email).
		s(attrName, link.Name).
		s(attrPicture, link.Picture).
		t(attrCreatedAt, link.CreatedAt).
		// The by-owner fan-out. GSI1PK is tenant-less because ListForUser is:
		// a user id is 16 random bytes (security.go:18-26), so USERID#<u> is
		// unambiguous on its own.
		sAlways(attrGSI1PK, gsi1UserID(link.UserID)).
		sAlways(attrGSI1SK, oauthGSI1SK(link.Provider, link.ProviderID))
}

// linkIDItem is the by-id pointer. Delete(id) carries only the id, which is not
// part of the canonical key, so the pointer is the only way to resolve it
// without a scan (data-model.md #55).
func linkIDItem(link auth.OAuthLinkedAccount) item {
	return item{}.
		sAlways(attrPK, linkIDPK(link.ID)).
		sAlways(attrSK, skLinkID).
		stamp(typeLinkID).
		sAlways(attrLinkID, link.ID).
		sAlways(attrUserID, link.UserID).
		sAlways(attrProvider, link.Provider).
		sAlways(attrProviderID, link.ProviderID)
}

func linkFromItem(m map[string]types.AttributeValue) (auth.OAuthLinkedAccount, error) {
	if err := checkVersion(m, typeLink); err != nil {
		return auth.OAuthLinkedAccount{}, err
	}
	link := auth.OAuthLinkedAccount{
		ID:         getS(m, attrLinkID),
		UserID:     getS(m, attrUserID),
		Provider:   getS(m, attrProvider),
		ProviderID: getS(m, attrProviderID),
		Email:      getS(m, attrEmail),
		Name:       getS(m, attrName),
		Picture:    getS(m, attrPicture),
	}
	var err error
	if link.CreatedAt, err = getTime(m, attrCreatedAt); err != nil {
		return auth.OAuthLinkedAccount{}, err
	}
	return link, nil
}

// Save writes a provider binding, replacing whatever binding that provider
// account had before — and, unlike the reference, leaving nothing behind when it
// does.
//
// **This is upstream bug nik2208/awesome-go-auth#37, and it is not reproduced.**
// MemoryLinkedAccounts (oauth.go:380-399) re-points byPrv[provider][providerID]
// at the new link and appends to the new user's slice, but never touches the old
// link's byID entry or the old user's slice. After a rebind, the previous owner's
// ListForUser still advertises a provider account that no longer signs them in,
// the old id still resolves through byID, and Delete(newID) unbinds the account
// while leaving the stale entry visible for ever. The bug is possible at all
// because that store keeps three indexes and updates two of them.
//
// Here there is one canonical item. Rebinding *overwrites* it, so the GSI1PK
// carrying the owner moves from USERID#<old> to USERID#<new> in the same write:
// the old owner's ListForUser stops returning it and the new owner's starts, with
// no window in between and nothing to clean up. The only thing that could go
// stale is the old LINKID#<id> pointer, and that is deleted inside the same
// transaction.
//
// The transaction is a compare-and-set on the binding the read observed, which is
// the ApplyEmailChange pattern (#22): the read supplies a key the interface does
// not carry, and decides nothing, because the write re-asserts what was read.
//
//	Put    OAUTH#<p>#<pid>   if attribute_not_exists(PK) OR linkId = :observed
//	Put    LINKID#<newId>    if attribute_not_exists(PK) OR (provider = :p AND providerId = :pid)
//	Delete LINKID#<observed> — only when a different id held the binding
//
// The first condition is what makes it atomic: if another caller rebound the
// account between the read and the write, this attempt is refused and re-reads
// rather than deleting a pointer that now belongs to somebody else. The second is
// ownership rather than mere absence, for the same reason the single-use token
// pointers are (§4.1): an ordinary retry of this very call must succeed, while a
// link id that already names a *different* provider account must fail loudly
// instead of orphaning the item it used to name.
func (l *LinkedAccounts) Save(ctx context.Context, link auth.OAuthLinkedAccount) error {
	s := l.store
	if err := checkID("link id", link.ID); err != nil {
		return err
	}
	if err := checkID("user id", link.UserID); err != nil {
		return err
	}
	if err := checkProvider(link.Provider); err != nil {
		return err
	}
	if err := checkProviderAccountID(link.ProviderID); err != nil {
		return err
	}

	canonical := key(oauthPK(link.Provider, link.ProviderID), skOAuth)
	for attempt := 0; ; attempt++ {
		observed, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
			TableName:      aws.String(s.table),
			Key:            canonical,
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return wrap("get linked account", err)
		}
		if len(observed.Item) > 0 {
			if err := checkVersion(observed.Item, typeLink); err != nil {
				return err
			}
		}
		observedID := getS(observed.Item, attrLinkID)

		// With nothing there, absence is the whole condition. With something
		// there, it must still be the same something: DynamoDB rejects an unused
		// expression value, so the alias only exists in the branch that names it.
		canonicalCondition := "attribute_not_exists(#PK)"
		canonicalNames := exprNames(attrPK)
		var canonicalValues map[string]types.AttributeValue
		if observedID != "" {
			canonicalCondition = "attribute_not_exists(#PK) OR #linkId = :observed"
			canonicalNames = exprNames(attrPK, attrLinkID)
			canonicalValues = map[string]types.AttributeValue{":observed": avS(observedID)}
		}

		items := []types.TransactWriteItem{
			{Put: &types.Put{
				TableName:                 aws.String(s.table),
				Item:                      linkItem(link),
				ConditionExpression:       aws.String(canonicalCondition),
				ExpressionAttributeNames:  canonicalNames,
				ExpressionAttributeValues: canonicalValues,
			}},
			{Put: &types.Put{
				TableName:                aws.String(s.table),
				Item:                     linkIDItem(link),
				ConditionExpression:      aws.String("attribute_not_exists(#PK) OR (#userId = :uid AND #provider = :p AND #providerId = :pid)"),
				ExpressionAttributeNames: exprNames(attrPK, attrUserID, attrProvider, attrProviderID),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":uid": avS(link.UserID),
					":p":   avS(link.Provider),
					":pid": avS(link.ProviderID),
				},
			}},
		}
		if observedID != "" && observedID != link.ID {
			// The stale pointer, dropped in the same transaction as the rebind.
			// Unconditional: the id it names no longer holds the binding, which
			// item 0's condition has just established, and deleting an absent item
			// succeeds.
			items = append(items, types.TransactWriteItem{Delete: &types.Delete{
				TableName: aws.String(s.table),
				Key:       key(linkIDPK(observedID), skLinkID),
			}})
		}
		err = s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{TransactItems: items})
		if err == nil {
			return nil
		}
		reasons, cancelled := txConditionFailures(err)
		if !cancelled {
			return wrap("save linked account", err)
		}
		if _, failed := txFailedAt(reasons, 1); failed {
			return fmt.Errorf("dynamodb: link id %q already names a different provider account", link.ID)
		}
		if _, failed := txFailedAt(reasons, 0); failed {
			if attempt == linkRebindAttempts-1 {
				return fmt.Errorf("%w: %s/%s", ErrLinkedAccountConflict, link.Provider, link.ProviderID)
			}
			if sleepErr := sleepCtx(ctx, backoff(attempt)); sleepErr != nil {
				return sleepErr
			}
			continue
		}
		return wrap("save linked account", err)
	}
}

// FindByProvider resolves the canonical item. One strongly-consistent GetItem,
// not an index query: this is the OAuth callback's identity resolution
// (oauth.go:305), and a stale read there is a failed sign-in or, worse, a second
// account for an identity that already has one.
func (l *LinkedAccounts) FindByProvider(ctx context.Context, provider, providerID string) (auth.OAuthLinkedAccount, error) {
	s := l.store
	if err := checkProvider(provider); err != nil {
		// A malformed provider cannot have a binding, and the caller-facing answer
		// is the same as an absent one. Returning the typed key error instead would
		// make DELETE /linked-accounts/{provider}/{id} — whose segments come
		// straight off the URL — answer differently for a hostile path than for an
		// unknown one.
		return auth.OAuthLinkedAccount{}, ErrLinkedAccountNotFound
	}
	if err := checkProviderAccountID(providerID); err != nil {
		return auth.OAuthLinkedAccount{}, ErrLinkedAccountNotFound
	}
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(oauthPK(provider, providerID), skOAuth),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.OAuthLinkedAccount{}, wrap("find linked account", err)
	}
	if len(out.Item) == 0 {
		return auth.OAuthLinkedAccount{}, ErrLinkedAccountNotFound
	}
	return linkFromItem(out.Item)
}

// ListForUser returns a user's bindings (data-model.md #54).
//
// The result is ordered by provider then provider account id, because GSI1SK is,
// and BatchGetItem does not preserve request order so it has to be restored.
// MemoryLinkedAccounts returns insertion order; the difference is wire-visible
// and is in CompatibilityNotes.
func (l *LinkedAccounts) ListForUser(ctx context.Context, userID string) ([]auth.OAuthLinkedAccount, error) {
	out, err := l.ownedLinksForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	sortLinks(out)
	return out, nil
}

// ownedLinksForUser resolves the by-owner index to the canonical items and keeps
// only the ones that still belong to userID.
//
// GSI1 → BatchGetItem, not GSI1 alone: the index projects three attributes on
// purpose, so that no second physical copy of anything exists that does not have
// to (§5), and the wire projection needs email, name and picture
// (oauth_wire.go:566-577).
//
// The ownership re-check is not a substitute for keying, and it is not the
// post-read filter §3 forbids: the query is still confined to USERID#<u>'s index
// partition and no other partition is reachable from here. It is a *staleness*
// guard, and it fails closed. GSI1 is eventually consistent, so a Save that
// rebinds a provider account moves GSI1PK from one owner to the next atomically in
// the canonical item while the old owner's index partition goes on advertising the
// entry for a while — and the canonical item, read strongly consistent below, is
// the only place the owner actually lives.
//
// Trusting the index for ownership instead has two consequences, both reproduced
// before this was written:
//
//   - ListForUser would show one user another user's provider binding, including
//     the email GET /linked-accounts renders.
//   - DeleteUser sweeps these keys with a BatchWriteItem, which cannot carry a
//     ConditionExpression, and OAUTH#<provider>#<providerId> is the same key
//     whoever owns it — so deleting a user would delete a live binding out from
//     under its current owner, stranding that provider identity.
func (l *LinkedAccounts) ownedLinksForUser(ctx context.Context, userID string) ([]auth.OAuthLinkedAccount, error) {
	s := l.store
	keys, err := l.keysForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		// Non-nil, so ListLinkedAccounts renders [] rather than null.
		return []auth.OAuthLinkedAccount{}, nil
	}
	items, err := s.batchGet(ctx, keys)
	if err != nil {
		return nil, wrap("list linked accounts", err)
	}
	out := make([]auth.OAuthLinkedAccount, 0, len(items))
	for _, m := range items {
		link, err := linkFromItem(m)
		if err != nil {
			return nil, err
		}
		if link.UserID != userID {
			// A stale index entry. Dropping it is the answer the index itself will
			// give once it catches up.
			continue
		}
		out = append(out, link)
	}
	return out, nil
}

// Delete removes a binding by link id (data-model.md #55).
//
// Absent is success, matching MemoryLinkedAccounts (oauth.go:423-426) and the
// route above it, which answers success unconditionally
// (oauth_wire.go:610-626). The canonical delete is conditional on the link id
// still holding the binding, so a Delete that arrives after somebody else rebound
// the provider account removes only its own stale pointer and leaves the live
// binding — the same ownership rule Save writes with, read back.
func (l *LinkedAccounts) Delete(ctx context.Context, id string) error {
	s := l.store
	if err := checkID("link id", id); err != nil {
		return err
	}
	pointerKey := key(linkIDPK(id), skLinkID)
	pointer, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            pointerKey,
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return wrap("get link pointer", err)
	}
	if len(pointer.Item) == 0 {
		return nil
	}
	if err := checkVersion(pointer.Item, typeLinkID); err != nil {
		return err
	}
	// Both come off an item this store wrote, never off the request.
	provider := getS(pointer.Item, attrProvider)
	providerID := getS(pointer.Item, attrProviderID)

	err = s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{
				TableName:                aws.String(s.table),
				Key:                      key(oauthPK(provider, providerID), skOAuth),
				ConditionExpression:      aws.String("#linkId = :id"),
				ExpressionAttributeNames: exprNames(attrLinkID),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":id": avS(id),
				},
			}},
			{Delete: &types.Delete{TableName: aws.String(s.table), Key: pointerKey}},
		},
	})
	if err != nil {
		if reasons, cancelled := txConditionFailures(err); cancelled {
			if _, failed := txFailedAt(reasons, 0); failed {
				// The binding is gone or belongs to another link id now. Drop the
				// pointer alone so nothing stale survives, and report success —
				// there is nothing left of this link either way.
				if _, delErr := s.api.DeleteItem(ctx, &awsddb.DeleteItemInput{
					TableName: aws.String(s.table),
					Key:       pointerKey,
				}); delErr != nil {
					return wrap("delete link pointer", delErr)
				}
				return nil
			}
		}
		return wrap("delete linked account", err)
	}
	return nil
}

// keysForUser returns the main-table keys of the linked accounts the by-owner
// index currently attributes to userID.
//
// They are *candidates*, not confirmed bindings: the index is eventually
// consistent, so ownership has to be re-read from the canonical item. Every caller
// therefore goes through ownedLinksForUser rather than using these keys directly.
func (l *LinkedAccounts) keysForUser(ctx context.Context, userID string) ([]map[string]types.AttributeValue, error) {
	s := l.store
	if err := checkID("user id", userID); err != nil {
		return nil, err
	}
	// No ConsistentRead: a GSI does not support it.
	items, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		IndexName:                aws.String(s.index),
		KeyConditionExpression:   aws.String("#GSI1PK = :owner AND begins_with(#GSI1SK, :prefix)"),
		ExpressionAttributeNames: exprNames(attrGSI1PK, attrGSI1SK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":owner": avS(gsi1UserID(userID)),
			// The prefix is what keeps the tenant memberships out: they share
			// GSI1PK=USERID#<u> and carry GSI1SK=TENANT#<t> (data-model.md §2.2).
			":prefix": avS(skOAuth + keySep),
		},
	}, s.maxLinkedAccounts)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap("query linked accounts for user", err)
	}
	out := make([]map[string]types.AttributeValue, 0, len(items))
	for _, m := range items {
		out = append(out, key(getS(m, attrPK), getS(m, attrSK)))
	}
	return out, nil
}

// sortLinks restores the order GSI1SK gave us, which BatchGetItem discarded.
func sortLinks(links []auth.OAuthLinkedAccount) {
	slices.SortFunc(links, func(a, b auth.OAuthLinkedAccount) int {
		if c := strings.Compare(a.Provider, b.Provider); c != 0 {
			return c
		}
		return strings.Compare(a.ProviderID, b.ProviderID)
	})
}

// linkKeysForUser returns every key DeleteUser has to sweep for a user's OAuth
// bindings: the canonical item and its by-id pointer (data-model.md #6, "links").
//
// It hangs off *Store rather than *LinkedAccounts because DeleteUser must sweep
// them whether or not the deployment wired the OAuth stores: an item this table
// holds outlives the interface that wrote it, and a binding left behind would
// keep resolving FindByProvider to a user who no longer exists.
//
// Both keys are rebuilt from the canonical item rather than taken from the index
// page, which is what makes the sweep safe. The index's linkId is exactly as stale
// as its GSI1PK, so after a rebind the old projection would have DeleteUser delete
// a pointer that no longer names anything and miss the one that does — on top of
// deleting a canonical item that now belongs to somebody else. See
// ownedLinksForUser.
func (s *Store) linkKeysForUser(ctx context.Context, userID string) ([]map[string]types.AttributeValue, error) {
	links, err := (&LinkedAccounts{store: s}).ownedLinksForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]types.AttributeValue, 0, len(links)*2)
	for _, link := range links {
		out = append(out, key(oauthPK(link.Provider, link.ProviderID), skOAuth))
		if link.ID != "" {
			out = append(out, key(linkIDPK(link.ID), skLinkID))
		}
	}
	return out, nil
}
