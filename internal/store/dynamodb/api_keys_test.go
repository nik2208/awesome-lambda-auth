package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

func sampleAPIKey(id, prefix, serviceID string, createdAt time.Time) auth.APIKeyRecord {
	return auth.APIKeyRecord{
		ID:         id,
		Prefix:     prefix,
		Name:       "ci",
		ServiceID:  serviceID,
		KeyHash:    "$2a$10$" + id,
		Scopes:     []string{"read", "write"},
		AllowedIPs: []string{"10.0.0.0/8"},
		IsActive:   true,
		CreatedAt:  createdAt,
	}
}

func TestAPIKeyRoundTripAndTwoKeySpaces(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	exp := time.Date(2030, 1, 2, 3, 4, 5, 6, time.UTC)
	want := sampleAPIKey("key_aaa", "ak_00000001", "svc-ci", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	want.ExpiresAt = &exp
	if err := store.Save(ctx, want); err != nil {
		t.Fatalf("save: %v", err)
	}

	byPrefix, err := store.FindByPrefix(ctx, want.Prefix)
	if err != nil {
		t.Fatalf("find by prefix: %v", err)
	}
	byID, err := store.FindByID(ctx, want.ID)
	if err != nil {
		t.Fatalf("find by id: %v", err)
	}
	if byPrefix.ID != want.ID || byID.Prefix != want.Prefix {
		t.Fatalf("the two key spaces disagree: %+v vs %+v", byPrefix, byID)
	}
	if byID.Name != want.Name || byID.ServiceID != want.ServiceID || byID.KeyHash != want.KeyHash {
		t.Fatalf("scalars lost: %+v", byID)
	}
	if fmt.Sprint(byID.Scopes) != fmt.Sprint(want.Scopes) ||
		fmt.Sprint(byID.AllowedIPs) != fmt.Sprint(want.AllowedIPs) {
		t.Fatalf("lists lost or reordered: %+v", byID)
	}
	if byID.ExpiresAt == nil || !byID.ExpiresAt.Equal(exp) {
		t.Fatalf("expiresAt = %v, want %v", byID.ExpiresAt, exp)
	}
	if !byID.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("createdAt = %v, want %v", byID.CreatedAt, want.CreatedAt)
	}
}

// TestAPIKeyNilScopesRoundTripAsNil: an L is written only when the slice is
// non-nil, so a record stored without scopes does not come back with [].
func TestAPIKeyNilScopesRoundTripAsNil(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	bare := auth.APIKeyRecord{ID: "key_bare", Prefix: "ak_bare0001", KeyHash: "h", IsActive: true}
	if err := store.Save(ctx, bare); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := store.FindByID(ctx, bare.ID)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.Scopes != nil || got.AllowedIPs != nil {
		t.Fatalf("nil slices came back as %#v / %#v", got.Scopes, got.AllowedIPs)
	}
}

func TestSaveRefusesACollision(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	first := sampleAPIKey("key_one", "ak_00000001", "svc", time.Now().UTC())
	if err := store.Save(ctx, first); err != nil {
		t.Fatalf("first save: %v", err)
	}

	// A prefix collision — expected around 77 000 live keys, since the prefix is
	// 32 bits — must be a loud error the caller can retry, never a silent
	// overwrite of a live key.
	samePrefix := sampleAPIKey("key_two", first.Prefix, "svc", time.Now().UTC())
	if err := store.Save(ctx, samePrefix); !errors.Is(err, ErrAPIKeyExists) {
		t.Fatalf("prefix collision = %v, want ErrAPIKeyExists", err)
	}
	sameID := sampleAPIKey(first.ID, "ak_00000002", "svc", time.Now().UTC())
	if err := store.Save(ctx, sameID); !errors.Is(err, ErrAPIKeyExists) {
		t.Fatalf("id collision = %v, want ErrAPIKeyExists", err)
	}
	// The incumbent is untouched by either.
	got, err := store.FindByID(ctx, first.ID)
	if err != nil || got.Prefix != first.Prefix {
		t.Fatalf("the live key was disturbed: %+v (%v)", got, err)
	}
}

// TestFindByPrefixIsActiveOnlyAndFindByIDIsNot is the trap the upstream authors
// flagged: the two finders are deliberate opposites.
func TestFindByPrefixIsActiveOnlyAndFindByIDIsNot(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	k := sampleAPIKey("key_rev", "ak_rev00001", "svc", time.Now().UTC())
	if err := store.Save(ctx, k); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.Revoke(ctx, k.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, err := store.FindByPrefix(ctx, k.Prefix); !errors.Is(err, auth.ErrAPIKeyNotFound) {
		t.Fatalf("FindByPrefix on a revoked key = %v, want ErrAPIKeyNotFound", err)
	}
	got, err := store.FindByID(ctx, k.ID)
	if err != nil {
		t.Fatalf("FindByID on a revoked key: %v — admin management needs it", err)
	}
	if got.IsActive {
		t.Fatal("revoke did not clear isActive")
	}

	// An expired key is still returned by both, because the contract names
	// IsActive and nothing else: Verify checks ExpiresAt itself.
	past := time.Now().UTC().Add(-time.Hour)
	exp := sampleAPIKey("key_exp", "ak_exp00001", "svc", time.Now().UTC())
	exp.ExpiresAt = &past
	if err := store.Save(ctx, exp); err != nil {
		t.Fatalf("save expired: %v", err)
	}
	if _, err := store.FindByPrefix(ctx, exp.Prefix); err != nil {
		t.Fatalf("FindByPrefix filtered on expiry, which is not its contract: %v", err)
	}
}

func TestRevokeAndUpdateLastUsedAreNoOpsForAnUnknownID(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	// Both routes await these and answer 200 with no lookup of their own, so an
	// error here would turn that 200 into a 500.
	if err := store.Revoke(ctx, "key_ghost"); err != nil {
		t.Fatalf("revoke unknown: %v", err)
	}
	if err := store.UpdateLastUsed(ctx, "key_ghost", time.Now()); err != nil {
		t.Fatalf("update last used on unknown: %v", err)
	}
	if err := store.Delete(ctx, "key_ghost"); err != nil {
		t.Fatalf("delete unknown: %v", err)
	}
	// An id the store could not even key is the same case.
	if err := store.Revoke(ctx, "not a valid id"); err != nil {
		t.Fatalf("revoke unkeyable: %v", err)
	}
}

// TestUpdateLastUsedIsThrottled pins §6.3's answer to one write per request: the
// condition, not a cache, so it holds across execution environments.
func TestUpdateLastUsedIsThrottled(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	k := sampleAPIKey("key_touch", "ak_touch001", "svc", time.Now().UTC())
	if err := store.Save(ctx, k); err != nil {
		t.Fatalf("save: %v", err)
	}

	first := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	if err := store.UpdateLastUsed(ctx, k.ID, first); err != nil {
		t.Fatalf("first stamp: %v", err)
	}
	// Inside the window: accepted as success and not written.
	if err := store.UpdateLastUsed(ctx, k.ID, first.Add(30*time.Second)); err != nil {
		t.Fatalf("throttled stamp reported an error: %v", err)
	}
	got, err := store.FindByID(ctx, k.ID)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(first) {
		t.Fatalf("lastUsedAt = %v, want the throttled-out first stamp %v", got.LastUsedAt, first)
	}

	// Past the window: written.
	later := first.Add(2 * apiKeyLastUsedThrottle)
	if err := store.UpdateLastUsed(ctx, k.ID, later); err != nil {
		t.Fatalf("later stamp: %v", err)
	}
	got, err = store.FindByID(ctx, k.ID)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(later) {
		t.Fatalf("lastUsedAt = %v, want %v", got.LastUsedAt, later)
	}
}

func TestDeleteRemovesBothItems(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	k := sampleAPIKey("key_del", "ak_del00001", "svc", time.Now().UTC())
	if err := store.Save(ctx, k); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.Delete(ctx, k.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	mustNotExist(t, client, store.table, apiKeyPK(k.Prefix), skAPIKey)
	mustNotExist(t, client, store.table, keyIDPK(k.ID), skKeyID)
	if _, err := store.FindByID(ctx, k.ID); !errors.Is(err, auth.ErrAPIKeyNotFound) {
		t.Fatalf("find after delete = %v, want ErrAPIKeyNotFound", err)
	}
	// A second delete succeeds, as the route expects.
	if err := store.Delete(ctx, k.ID); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

// TestListAllIsNewestFirstWithAnIDTiebreak is the order the core declares
// normative and the reason the sort key holds a complemented timestamp: a plain
// timestamp read backwards would break ties by ID descending, which is a
// different total order.
func TestListAllIsNewestFirstWithAnIDTiebreak(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	// Two share an instant, which is what makes the tiebreak observable — and a
	// backing column with second resolution makes that common.
	for _, k := range []auth.APIKeyRecord{
		sampleAPIKey("key_b", "ak_b0000001", "svc", base),
		sampleAPIKey("key_a", "ak_a0000001", "svc", base),
		sampleAPIKey("key_new", "ak_n0000001", "svc", base.Add(time.Hour)),
		sampleAPIKey("key_old", "ak_o0000001", "svc", base.Add(-time.Hour)),
	} {
		if err := store.Save(ctx, k); err != nil {
			t.Fatalf("save %s: %v", k.ID, err)
		}
	}
	// A record with no CreatedAt at all sorts last, after every record that has
	// one.
	if err := store.Save(ctx, sampleAPIKey("key_zero", "ak_z0000001", "svc", time.Time{})); err != nil {
		t.Fatalf("save zero: %v", err)
	}

	got, err := store.ListAll(ctx, 100, 0)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	var ids []string
	for _, k := range got {
		ids = append(ids, k.ID)
	}
	want := []string{"key_new", "key_a", "key_b", "key_old", "key_zero"}
	if fmt.Sprint(ids) != fmt.Sprint(want) {
		t.Fatalf("ListAll = %v, want CreatedAt desc then ID asc %v", ids, want)
	}
}

func TestListAllPaging(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		k := sampleAPIKey(fmt.Sprintf("key_%02d", i), fmt.Sprintf("ak_%08d", i), "svc", base.Add(time.Duration(i)*time.Hour))
		if err := store.Save(ctx, k); err != nil {
			t.Fatalf("save: %v", err)
		}
	}

	seen := map[string]int{}
	for offset := 0; ; offset += 2 {
		page, err := store.ListAll(ctx, 2, offset)
		if err != nil {
			t.Fatalf("page at %d: %v", offset, err)
		}
		for _, k := range page {
			seen[k.ID]++
		}
		if len(page) < 2 {
			break
		}
	}
	if len(seen) != 5 {
		t.Fatalf("walk saw %d keys, want 5: %v", len(seen), seen)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("walk saw %s %d times", id, n)
		}
	}
}

func TestListByServiceIDScopesAndOrders(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	for _, k := range []auth.APIKeyRecord{
		sampleAPIKey("key_ci1", "ak_ci000001", "ci", base),
		sampleAPIKey("key_ci2", "ak_ci000002", "ci", base.Add(time.Hour)),
		sampleAPIKey("key_web", "ak_web00001", "web", base),
		// An unset service id is a real value: the reference's
		// listByServiceId("") asks for exactly these.
		sampleAPIKey("key_none", "ak_none0001", "", base),
	} {
		if err := store.Save(ctx, k); err != nil {
			t.Fatalf("save %s: %v", k.ID, err)
		}
	}

	ci, err := store.ListByServiceID(ctx, "ci")
	if err != nil {
		t.Fatalf("list by service: %v", err)
	}
	var ids []string
	for _, k := range ci {
		ids = append(ids, k.ID)
	}
	if fmt.Sprint(ids) != fmt.Sprint([]string{"key_ci2", "key_ci1"}) {
		t.Fatalf("ListByServiceID(ci) = %v, want newest first", ids)
	}

	none, err := store.ListByServiceID(ctx, "")
	if err != nil {
		t.Fatalf("list by empty service: %v", err)
	}
	if len(none) != 1 || none[0].ID != "key_none" {
		t.Fatalf("ListByServiceID(\"\") = %+v, want the one key with no service id", none)
	}

	// Revoked keys are listed too: the interface says "active or not".
	if err := store.Revoke(ctx, "key_ci1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	ci, err = store.ListByServiceID(ctx, "ci")
	if err != nil {
		t.Fatalf("list after revoke: %v", err)
	}
	if len(ci) != 2 {
		t.Fatalf("revoking dropped a key from the service listing: %+v", ci)
	}
}

// TestAPIKeyItemsCarryNoTTL. FindByID must return an expired record, so a TTL
// keyed off ExpiresAt would delete exactly what the method exists to return.
// §2.2 marked the TTL "optional"; it is none.
func TestAPIKeyItemsCarryNoTTL(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	past := time.Now().UTC().Add(-time.Hour)
	k := sampleAPIKey("key_ttl", "ak_ttl00001", "svc", time.Now().UTC())
	k.ExpiresAt = &past
	if err := store.Save(ctx, k); err != nil {
		t.Fatalf("save: %v", err)
	}
	for _, where := range []struct{ pk, sk string }{
		{apiKeyPK(k.Prefix), skAPIKey},
		{keyIDPK(k.ID), skKeyID},
	} {
		m := rawItem(t, client, store.table, where.pk, where.sk)
		if _, hasTTL := m[attrTTL]; hasTTL {
			t.Fatalf("%s/%s carries a ttl; an expired key must stay readable", where.pk, where.sk)
		}
	}
}
