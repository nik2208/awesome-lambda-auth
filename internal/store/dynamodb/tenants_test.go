package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

func TestTenantDirectoryRoundTrip(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	want := auth.Tenant{
		ID:       "acme",
		Name:     "Acme Corp",
		IsActive: true,
		Config: map[string]any{
			"plan":     "enterprise",
			"seats":    float64(250),
			"trial":    false,
			"features": []any{"sso", "scim"},
			"branding": map[string]any{"logo": "https://cdn.example.test/a.png"},
		},
	}
	created, err := store.CreateTenant(ctx, want)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if created.CreatedAt.IsZero() {
		t.Fatal("CreateTenant returned a tenant with no creation time")
	}

	got, err := store.GetTenantByID(ctx, "acme")
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if got.Name != want.Name || !got.IsActive {
		t.Fatalf("scalars lost: %+v", got)
	}
	if fmt.Sprint(got.Config["features"]) != fmt.Sprint(want.Config["features"]) {
		t.Fatalf("nested list lost: %#v", got.Config["features"])
	}
	// Numbers come back as float64, which is the type they had on the way in
	// through JSON and the type this codec documents.
	if seats, ok := got.Config["seats"].(float64); !ok || seats != 250 {
		t.Fatalf("number decoded as %T (%v), want float64 250", got.Config["seats"], got.Config["seats"])
	}
	if branding, ok := got.Config["branding"].(map[string]any); !ok || branding["logo"] == "" {
		t.Fatalf("nested map lost: %#v", got.Config["branding"])
	}
}

func TestCreateTenantRefusesADuplicate(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if _, err := store.CreateTenant(ctx, auth.Tenant{ID: "acme", Name: "first"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := store.CreateTenant(ctx, auth.Tenant{ID: "acme", Name: "second"})
	if !errors.Is(err, auth.ErrAlreadyExists) {
		t.Fatalf("duplicate create = %v, want ErrAlreadyExists", err)
	}
	// The condition is on the sort key, not the partition key — every tenant
	// shares the TENANTS partition, so a second *different* tenant must still
	// land.
	if _, err := store.CreateTenant(ctx, auth.Tenant{ID: "globex"}); err != nil {
		t.Fatalf("second distinct tenant refused: %v", err)
	}
}

func TestGetAllTenantsIsIDAscending(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	for _, id := range []string{"globex", "acme", "initech"} {
		if _, err := store.CreateTenant(ctx, auth.Tenant{ID: id}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	got, err := store.GetAllTenants(ctx)
	if err != nil {
		t.Fatalf("get all tenants: %v", err)
	}
	var ids []string
	for _, tn := range got {
		ids = append(ids, tn.ID)
	}
	if fmt.Sprint(ids) != fmt.Sprint([]string{"acme", "globex", "initech"}) {
		t.Fatalf("GetAllTenants = %v, want id-ascending", ids)
	}
}

func TestUpdateAndDeleteTenantOnAnUnknownID(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if err := store.UpdateTenant(ctx, "ghost", auth.Tenant{Name: "x"}); !errors.Is(err, auth.ErrTenantNotFound) {
		t.Fatalf("update unknown = %v, want ErrTenantNotFound", err)
	}
	if _, err := store.GetTenantByID(ctx, "ghost"); !errors.Is(err, auth.ErrTenantNotFound) {
		t.Fatalf("get unknown = %v, want ErrTenantNotFound", err)
	}
	// Delete is unconditional, matching MemoryTenantStore.
	if err := store.DeleteTenant(ctx, "ghost"); err != nil {
		t.Fatalf("delete unknown: %v", err)
	}
}

func TestUpdateTenantSetsTheThreeMutableFields(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	created, err := store.CreateTenant(ctx, auth.Tenant{
		ID: "acme", Name: "Acme", IsActive: true,
		Config: map[string]any{"plan": "starter"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.UpdateTenant(ctx, "acme", auth.Tenant{
		Name: "Acme Ltd", IsActive: false,
		Config: map[string]any{"plan": "enterprise"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := store.GetTenantByID(ctx, "acme")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "Acme Ltd" || got.IsActive {
		t.Fatalf("mutable fields not applied: %+v", got)
	}
	if got.Config["plan"] != "enterprise" {
		t.Fatalf("config not replaced: %#v", got.Config)
	}
	// CreatedAt is not a caller's to move, so the update leaves it alone.
	if !got.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("createdAt moved: %v, want %v", got.CreatedAt, created.CreatedAt)
	}
}

// TestMembershipsAreWrittenByCreateUserAndByAssociate is the property that lets
// the two writers coexist: CreateUser has always written a membership, and
// AssociateUserWithTenant writes the same item.
func TestMembershipsAreWrittenByCreateUserAndByAssociate(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	for _, id := range []string{"acme", "globex"} {
		if _, err := store.CreateTenant(ctx, auth.Tenant{ID: id}); err != nil {
			t.Fatalf("create tenant %s: %v", id, err)
		}
	}
	user := sampleUser("acme")
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	members, err := store.GetUsersForTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("users for acme: %v", err)
	}
	if fmt.Sprint(members) != fmt.Sprint([]string{user.ID}) {
		t.Fatalf("CreateUser did not leave a membership: %v", members)
	}

	if err := store.AssociateUserWithTenant(ctx, user.ID, "globex"); err != nil {
		t.Fatalf("associate: %v", err)
	}
	// Re-associating is a no-op, which is what lets the two writers not know
	// about each other.
	if err := store.AssociateUserWithTenant(ctx, user.ID, "acme"); err != nil {
		t.Fatalf("re-associate: %v", err)
	}

	tenants, err := store.GetTenantsForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("tenants for user: %v", err)
	}
	var ids []string
	for _, tn := range tenants {
		ids = append(ids, tn.ID)
	}
	if fmt.Sprint(ids) != fmt.Sprint([]string{"acme", "globex"}) {
		t.Fatalf("tenants for user = %v, want id-ascending [acme globex]", ids)
	}

	if err := store.DisassociateUserFromTenant(ctx, user.ID, "globex"); err != nil {
		t.Fatalf("disassociate: %v", err)
	}
	tenants, err = store.GetTenantsForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("tenants after disassociate: %v", err)
	}
	if len(tenants) != 1 || tenants[0].ID != "acme" {
		t.Fatalf("disassociate left %v", tenants)
	}
	// The user's own TenantID is a different relation and is untouched.
	back, err := store.GetUserByID(ctx, user.ID, "acme")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if back.TenantID != "acme" {
		t.Fatalf("disassociating moved the user's own tenant to %q", back.TenantID)
	}
}

func TestAssociateRefusesAnUnknownTenant(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	err := store.AssociateUserWithTenant(ctx, uniqueID("usr"), "ghost")
	if !errors.Is(err, auth.ErrTenantNotFound) {
		t.Fatalf("associate with an unknown tenant = %v, want ErrTenantNotFound", err)
	}
}

// TestGetTenantsForUserDropsDeletedTenants. MemoryTenantStore looks each id up
// in byID and skips a miss; DeleteTenant here sweeps the memberships, so the
// only way to reach this state is the sweep lagging — which it can.
func TestGetTenantsForUserDropsDeletedTenants(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if _, err := store.CreateTenant(ctx, auth.Tenant{ID: "acme"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	user := sampleUser("acme")
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	// Remove the directory entry only, leaving the membership.
	if err := store.deleteKeys(ctx, []map[string]types.AttributeValue{
		key(tenantsPK, tenantDirSK("acme")),
	}); err != nil {
		t.Fatalf("raw delete: %v", err)
	}

	got, err := store.GetTenantsForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("tenants for user: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a membership named a deleted tenant and it was reported: %+v", got)
	}
}

func TestDeleteTenantSweepsMembershipsButNotUsers(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if _, err := store.CreateTenant(ctx, auth.Tenant{ID: "acme"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	user := sampleUser("acme")
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	if err := store.DeleteTenant(ctx, "acme"); err != nil {
		t.Fatalf("delete tenant: %v", err)
	}
	members, err := store.GetUsersForTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("users for tenant: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("memberships survived: %v", members)
	}
	// The user itself is untouched: deleting a tenant is an administrative
	// tidy-up, not an account deletion.
	if _, err := store.GetUserByID(ctx, user.ID, "acme"); err != nil {
		t.Fatalf("deleting the tenant deleted the user: %v", err)
	}
}
