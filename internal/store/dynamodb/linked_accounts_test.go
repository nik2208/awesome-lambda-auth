package dynamodb

import (
	"context"
	"errors"
	"testing"
	"time"

	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	auth "github.com/nik2208/awesome-go-auth"
)

func sampleLink(userID, provider, providerID string) auth.OAuthLinkedAccount {
	return auth.OAuthLinkedAccount{
		ID:         uniqueID("lnk"),
		UserID:     userID,
		Provider:   provider,
		ProviderID: providerID,
		Email:      "linked@example.test",
		Name:       "Linked Person",
		Picture:    "https://cdn.example.test/avatar.png",
		CreatedAt:  time.Now().UTC().Truncate(time.Millisecond),
	}
}

func TestLinkedAccountRoundTrip(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	links := store.LinkedAccounts()
	ctx := context.Background()

	user := newUser(t, store, "acme")
	link := sampleLink(user.ID, "google", "sub-"+randomHex(8))
	if err := links.Save(ctx, link); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := links.FindByProvider(ctx, link.Provider, link.ProviderID)
	if err != nil {
		t.Fatalf("FindByProvider: %v", err)
	}
	if got.ID != link.ID || got.UserID != link.UserID || got.Provider != link.Provider || got.ProviderID != link.ProviderID {
		t.Errorf("FindByProvider = %+v, want the saved identity %+v", got, link)
	}
	// Email, Name and Picture are what GET /linked-accounts renders
	// (oauth_wire.go:566-577), and they are not in the index keys, so their
	// round trip is the reason ListForUser fetches the main-table item.
	if got.Email != link.Email || got.Name != link.Name || got.Picture != link.Picture {
		t.Errorf("profile columns = (%q,%q,%q), want (%q,%q,%q)",
			got.Email, got.Name, got.Picture, link.Email, link.Name, link.Picture)
	}
	if !got.CreatedAt.Equal(link.CreatedAt) {
		t.Errorf("CreatedAt = %s, want %s", got.CreatedAt, link.CreatedAt)
	}

	listed, err := links.ListForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != link.ID {
		t.Fatalf("ListForUser = %+v, want exactly the saved link", listed)
	}
	if listed[0].Email != link.Email {
		t.Errorf("ListForUser dropped the profile columns: %+v", listed[0])
	}

	if err := links.Delete(ctx, link.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	mustNotExist(t, client, store.table, oauthPK(link.Provider, link.ProviderID), skOAuth)
	mustNotExist(t, client, store.table, linkIDPK(link.ID), skLinkID)
	if _, err := links.FindByProvider(ctx, link.Provider, link.ProviderID); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Errorf("FindByProvider after Delete = %v, want ErrLinkedAccountNotFound", err)
	}
}

// TestLinkedAccountHasNoTenantAttribute pins a design decision that would
// otherwise be invisible: auth.OAuthLinkedAccount has no tenant field, so
// inventing one on the item would invent semantics (data-model.md §5).
func TestLinkedAccountHasNoTenantAttribute(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	user := newUser(t, store, "acme")
	link := sampleLink(user.ID, "github", "42")
	if err := store.LinkedAccounts().Save(ctx, link); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw := rawItem(t, client, store.table, oauthPK(link.Provider, link.ProviderID), skOAuth)
	if _, present := raw[attrTenantID]; present {
		t.Errorf("linked account carries %s = %v; the interface has no tenant and the store must not invent one",
			attrTenantID, raw[attrTenantID])
	}
	if got := getS(raw, attrGSI1PK); got != gsi1UserID(user.ID) {
		t.Errorf("GSI1PK = %q, want %q — the by-owner fan-out is tenant-less by construction", got, gsi1UserID(user.ID))
	}
}

func TestLinkedAccountSaveIsRetrySafe(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	links := store.LinkedAccounts()
	ctx := context.Background()

	user := newUser(t, store, "acme")
	link := sampleLink(user.ID, "google", "sub-"+randomHex(8))
	for i := range 3 {
		if err := links.Save(ctx, link); err != nil {
			t.Fatalf("Save attempt %d: %v", i, err)
		}
	}
	listed, err := links.ListForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("three identical Saves produced %d links, want 1: %+v", len(listed), listed)
	}
}

// TestRebindingLeavesNoStaleEntry is the upstream bug this store must not
// reproduce: nik2208/awesome-go-auth#37.
//
// MemoryLinkedAccounts re-points its provider index at the new link but never
// touches the old link's byID entry or the old owner's slice (oauth.go:380-399),
// so after a rebind the previous owner's ListForUser still advertises a provider
// account that no longer signs them in, and the old id still resolves. Here the
// canonical item is overwritten — which moves GSI1PK from one owner to the other
// atomically — and the superseded LINKID pointer is deleted in the same
// transaction.
func TestRebindingLeavesNoStaleEntry(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	links := store.LinkedAccounts()
	ctx := context.Background()

	alice := newUser(t, store, "acme")
	bob := newUser(t, store, "acme")
	providerID := "sub-" + randomHex(8)

	first := sampleLink(alice.ID, "google", providerID)
	if err := links.Save(ctx, first); err != nil {
		t.Fatalf("Save first: %v", err)
	}
	second := sampleLink(bob.ID, "google", providerID)
	if err := links.Save(ctx, second); err != nil {
		t.Fatalf("Save rebind: %v", err)
	}

	// 1. The binding resolves to the new owner.
	got, err := links.FindByProvider(ctx, "google", providerID)
	if err != nil {
		t.Fatalf("FindByProvider: %v", err)
	}
	if got.UserID != bob.ID || got.ID != second.ID {
		t.Errorf("FindByProvider = user %q link %q, want user %q link %q", got.UserID, got.ID, bob.ID, second.ID)
	}

	// 2. The previous owner no longer lists it. This is the half the reference
	//    gets wrong.
	aliceLinks, err := links.ListForUser(ctx, alice.ID)
	if err != nil {
		t.Fatalf("ListForUser(alice): %v", err)
	}
	if len(aliceLinks) != 0 {
		t.Errorf("the previous owner still lists %d binding(s) after the rebind: %+v", len(aliceLinks), aliceLinks)
	}
	bobLinks, err := links.ListForUser(ctx, bob.ID)
	if err != nil {
		t.Fatalf("ListForUser(bob): %v", err)
	}
	if len(bobLinks) != 1 || bobLinks[0].ID != second.ID {
		t.Errorf("new owner lists %+v, want exactly the new link", bobLinks)
	}

	// 3. The superseded id resolves to nothing at all.
	mustNotExist(t, client, store.table, linkIDPK(first.ID), skLinkID)

	// 4. And deleting it cannot take the live binding down with it. The reference
	//    would delete the provider index entry here, because its byID lookup for
	//    the stale id still succeeds.
	if err := links.Delete(ctx, first.ID); err != nil {
		t.Fatalf("Delete(stale id): %v", err)
	}
	if got, err := links.FindByProvider(ctx, "google", providerID); err != nil || got.ID != second.ID {
		t.Errorf("after deleting the stale id the live binding is %+v (err %v), want link %q", got, err, second.ID)
	}
}

// TestRebindingToTheSameOwnerLeavesOneEntry covers the case the core actually
// produces most often: LinkVerify mints a fresh link id on every call
// (oauth_wire.go:781-795), so re-linking the same provider account to the same
// user arrives as a new id for an existing binding.
func TestRebindingToTheSameOwnerLeavesOneEntry(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	links := store.LinkedAccounts()
	ctx := context.Background()

	user := newUser(t, store, "acme")
	providerID := "sub-" + randomHex(8)
	first := sampleLink(user.ID, "google", providerID)
	second := sampleLink(user.ID, "google", providerID)

	if err := links.Save(ctx, first); err != nil {
		t.Fatalf("Save first: %v", err)
	}
	if err := links.Save(ctx, second); err != nil {
		t.Fatalf("Save second: %v", err)
	}

	listed, err := links.ListForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != second.ID {
		t.Fatalf("ListForUser = %+v, want exactly the newest link", listed)
	}
	mustNotExist(t, client, store.table, linkIDPK(first.ID), skLinkID)
	if raw := rawItem(t, client, store.table, linkIDPK(second.ID), skLinkID); len(raw) == 0 {
		t.Error("the new link id has no pointer, so Delete(id) could never find it")
	}
}

// TestSaveRefusesALinkIDBoundToAnotherAccount is the ownership half of the
// pointer condition. A reused link id naming a different provider account would
// otherwise orphan the item it used to name.
func TestSaveRefusesALinkIDBoundToAnotherAccount(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	links := store.LinkedAccounts()
	ctx := context.Background()

	user := newUser(t, store, "acme")
	first := sampleLink(user.ID, "google", "sub-"+randomHex(8))
	if err := links.Save(ctx, first); err != nil {
		t.Fatalf("Save first: %v", err)
	}

	clash := sampleLink(user.ID, "github", "99")
	clash.ID = first.ID
	if err := links.Save(ctx, clash); err == nil {
		t.Fatal("Save reused a link id for a different provider account and reported success")
	}
	// The first binding is untouched.
	if got, err := links.FindByProvider(ctx, first.Provider, first.ProviderID); err != nil || got.ID != first.ID {
		t.Errorf("first binding = %+v (err %v), want link %q intact", got, err, first.ID)
	}
	if _, err := links.FindByProvider(ctx, clash.Provider, clash.ProviderID); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Errorf("the refused binding was written anyway: %v", err)
	}
}

func TestDeleteUnknownLinkIDSucceeds(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	// MemoryLinkedAccounts returns nil for an id it has never seen
	// (oauth.go:423-426), and UnlinkAccount answers success unconditionally.
	if err := store.LinkedAccounts().Delete(ctx, uniqueID("lnk")); err != nil {
		t.Fatalf("Delete(unknown) = %v, want nil", err)
	}
}

func TestFindByProviderRejectsForgedSegments(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	links := store.LinkedAccounts()
	ctx := context.Background()

	// The provider occupies a middle key segment, so a '#' in it would make
	// OAUTH#<provider>#<providerId> ambiguous. It arrives from a URL path
	// parameter on DELETE /linked-accounts/{provider}/{providerAccountId}, so this
	// is reachable from the wire.
	if _, err := links.FindByProvider(ctx, "goo#gle", "sub-1"); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Errorf("FindByProvider with a '#' in the provider = %v, want ErrLinkedAccountNotFound", err)
	}
	if _, err := links.FindByProvider(ctx, "google", ""); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Errorf("FindByProvider with an empty account id = %v, want ErrLinkedAccountNotFound", err)
	}

	user := newUser(t, store, "acme")
	forged := sampleLink(user.ID, "goo#gle", "sub-1")
	if err := links.Save(ctx, forged); !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("Save with a '#' in the provider = %v, want ErrInvalidIdentifier", err)
	}
	empty := sampleLink(user.ID, "google", "")
	if err := links.Save(ctx, empty); !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("Save with an empty provider account id = %v, want ErrInvalidIdentifier", err)
	}
}

// TestListForUserIgnoresOtherOwnedItems: the tenant membership shares
// GSI1PK=USERID#<u> with the linked accounts (data-model.md §2.2), so the
// begins_with on GSI1SK is load-bearing rather than decoration.
func TestListForUserIgnoresOtherOwnedItems(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	links := store.LinkedAccounts()
	ctx := context.Background()

	// CreateUser writes TENANT#<t>/MEMBER#<u> with GSI1PK=USERID#<u>.
	user := newUser(t, store, "acme")
	listed, err := links.ListForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("ListForUser returned %+v for a user with no links; the tenant membership leaked into the query", listed)
	}
	if listed == nil {
		t.Error("ListForUser returned nil; the wire projection must render [] rather than null")
	}
}

// TestListForUserOrdersByProviderThenAccount pins the ordering
// CompatibilityNotes() advertises. BatchGetItem does not preserve request order,
// so without the explicit sort this is whatever DynamoDB felt like.
func TestListForUserOrdersByProviderThenAccount(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	links := store.LinkedAccounts()
	ctx := context.Background()
	user := newUser(t, store, "acme")

	for _, pair := range [][2]string{{"google", "sub-b"}, {"github", "2"}, {"google", "sub-a"}, {"github", "1"}} {
		if err := links.Save(ctx, sampleLink(user.ID, pair[0], pair[1])); err != nil {
			t.Fatalf("Save %v: %v", pair, err)
		}
	}
	listed, err := links.ListForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	want := [][2]string{{"github", "1"}, {"github", "2"}, {"google", "sub-a"}, {"google", "sub-b"}}
	if len(listed) != len(want) {
		t.Fatalf("ListForUser returned %d links, want %d: %+v", len(listed), len(want), listed)
	}
	for i, w := range want {
		if listed[i].Provider != w[0] || listed[i].ProviderID != w[1] {
			t.Errorf("link %d = %s/%s, want %s/%s", i, listed[i].Provider, listed[i].ProviderID, w[0], w[1])
		}
	}
}

// TestListForUserRefusesRatherThanTruncates: the interface has no cursor
// (data-model.md §8.6), so the only honest options are to refuse or to lie about
// which providers can sign the account in.
func TestListForUserRefusesRatherThanTruncates(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t, func(o *Options) { o.MaxLinkedAccountsPerUser = 2 })
	links := store.LinkedAccounts()
	ctx := context.Background()
	user := newUser(t, store, "acme")

	for i := range 3 {
		if err := links.Save(ctx, sampleLink(user.ID, "google", "sub-"+string(rune('a'+i)))); err != nil {
			t.Fatalf("Save %d: %v", i, err)
		}
	}
	if _, err := links.ListForUser(ctx, user.ID); !errors.Is(err, ErrResultTooLarge) {
		t.Fatalf("ListForUser over the cap = %v, want ErrResultTooLarge", err)
	}
}

// TestDeleteUserSweepsLinkedAccounts covers data-model.md #6's "links": a binding
// that outlived its user would keep resolving FindByProvider to somebody who no
// longer exists.
func TestDeleteUserSweepsLinkedAccounts(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	links := store.LinkedAccounts()
	ctx := context.Background()

	user := newUser(t, store, "acme")
	link := sampleLink(user.ID, "google", "sub-"+randomHex(8))
	if err := links.Save(ctx, link); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.DeleteUser(ctx, user.ID, "acme"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	mustNotExist(t, client, store.table, oauthPK(link.Provider, link.ProviderID), skOAuth)
	mustNotExist(t, client, store.table, linkIDPK(link.ID), skLinkID)
	if _, err := links.FindByProvider(ctx, link.Provider, link.ProviderID); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Errorf("FindByProvider after DeleteUser = %v, want ErrLinkedAccountNotFound", err)
	}
}

// assertSingleBinding is the invariant the rebind race asserts: one canonical
// item, one pointer, and that pointer is the canonical item's.
func assertSingleBinding(t *testing.T, store *Store, client *awsddb.Client, provider, providerID string, candidates []auth.OAuthLinkedAccount) auth.OAuthLinkedAccount {
	t.Helper()
	ctx := context.Background()

	live, err := store.LinkedAccounts().FindByProvider(ctx, provider, providerID)
	if err != nil {
		t.Fatalf("FindByProvider: %v", err)
	}
	for _, c := range candidates {
		raw := rawItem(t, client, store.table, linkIDPK(c.ID), skLinkID)
		if c.ID == live.ID {
			if len(raw) == 0 {
				t.Errorf("the live link %q has no pointer", c.ID)
			}
			continue
		}
		if len(raw) != 0 {
			t.Errorf("superseded link %q still has a pointer: %v", c.ID, raw)
		}
		owned, err := store.LinkedAccounts().ListForUser(ctx, c.UserID)
		if err != nil {
			t.Fatalf("ListForUser(%s): %v", c.UserID, err)
		}
		if c.UserID != live.UserID && len(owned) != 0 {
			t.Errorf("superseded owner %q still lists %+v", c.UserID, owned)
		}
	}
	return live
}
