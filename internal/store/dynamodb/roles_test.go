package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	auth "github.com/nik2208/awesome-go-auth"
)

func TestRoleDirectoryListsEveryDefinition(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	// Out of order on the way in, and one of them with no permissions at all:
	// "roles with no permissions are still roles and are still listed".
	if err := store.CreateRole(ctx, "editor", []string{"post:write"}); err != nil {
		t.Fatalf("create editor: %v", err)
	}
	if err := store.CreateRole(ctx, "admin", []string{"user:delete", "user:read"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := store.CreateRole(ctx, "observer", nil); err != nil {
		t.Fatalf("create observer: %v", err)
	}

	got, err := store.GetAllRoles(ctx)
	if err != nil {
		t.Fatalf("get all roles: %v", err)
	}
	want := []string{"admin", "editor", "observer"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("GetAllRoles = %v, want name-ascending %v", got, want)
	}

	perms, err := store.GetPermissionsForRole(ctx, "observer")
	if err != nil {
		t.Fatalf("permissions for observer: %v", err)
	}
	if len(perms) != 0 {
		t.Fatalf("a role created with no permissions has %v", perms)
	}
}

// TestCreateRoleResetsRatherThanRefuses pins MemoryRolesPermissionsStore's
// behaviour: it assigns a fresh set over whatever was there, so no
// ErrAlreadyExists is invented for a case the reference does not have.
func TestCreateRoleResetsRatherThanRefuses(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if err := store.CreateRole(ctx, "admin", []string{"a", "b"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if err := store.CreateRole(ctx, "admin", []string{"c"}); err != nil {
		t.Fatalf("second create: %v", err)
	}
	got, err := store.GetPermissionsForRole(ctx, "admin")
	if err != nil {
		t.Fatalf("permissions: %v", err)
	}
	if fmt.Sprint(got) != fmt.Sprint([]string{"c"}) {
		t.Fatalf("permissions after reset = %v, want [c]", got)
	}
}

func TestRolePermissionsAreASet(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if err := store.CreateRole(ctx, "admin", []string{"read", "read"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.AddPermissionToRole(ctx, "admin", "write"); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Granting twice is a no-op, which is what makes the write read-free.
	if err := store.AddPermissionToRole(ctx, "admin", "write"); err != nil {
		t.Fatalf("add again: %v", err)
	}
	got, err := store.GetPermissionsForRole(ctx, "admin")
	if err != nil {
		t.Fatalf("permissions: %v", err)
	}
	if fmt.Sprint(got) != fmt.Sprint([]string{"read", "write"}) {
		t.Fatalf("permissions = %v, want [read write]", got)
	}

	if err := store.RemovePermissionFromRole(ctx, "admin", "write"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := store.RemovePermissionFromRole(ctx, "admin", "read"); err != nil {
		t.Fatalf("remove last: %v", err)
	}
	// Emptying the set removes the attribute, which is the same state a role
	// created with no permissions is in — so the two need no reconciling.
	got, err = store.GetPermissionsForRole(ctx, "admin")
	if err != nil {
		t.Fatalf("permissions after emptying: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("permissions after emptying = %v, want none", got)
	}
	roles, err := store.GetAllRoles(ctx)
	if err != nil {
		t.Fatalf("get all roles: %v", err)
	}
	if fmt.Sprint(roles) != fmt.Sprint([]string{"admin"}) {
		t.Fatalf("emptying the permission set lost the role: %v", roles)
	}
}

// TestAddPermissionCreatesTheRoleButRemoveDoesNot. The memory store creates on
// grant (`if s.rolePermissions[role] == nil`) and deletes from a nil map on
// revoke. Here the asymmetry has teeth: an UpdateItem whose only action is a
// DELETE would still bring the item into existence.
func TestAddPermissionCreatesTheRoleButRemoveDoesNot(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if err := store.RemovePermissionFromRole(ctx, "ghost", "read"); err != nil {
		t.Fatalf("revoke from an undefined role: %v", err)
	}
	roles, err := store.GetAllRoles(ctx)
	if err != nil {
		t.Fatalf("get all roles: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("revoking from an undefined role defined it: %v", roles)
	}

	if err := store.AddPermissionToRole(ctx, "grown", "read"); err != nil {
		t.Fatalf("grant to an undefined role: %v", err)
	}
	roles, err = store.GetAllRoles(ctx)
	if err != nil {
		t.Fatalf("get all roles: %v", err)
	}
	if fmt.Sprint(roles) != fmt.Sprint([]string{"grown"}) {
		t.Fatalf("grant did not create the role: %v", roles)
	}
}

func TestAddRoleToUserRefusesAnUndefinedRole(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	err := store.AddRoleToUser(ctx, uniqueID("usr"), "nosuchrole", "acme")
	if !errors.Is(err, auth.ErrRoleNotFound) {
		t.Fatalf("assign an undefined role = %v, want ErrRoleNotFound", err)
	}
}

// TestRoleAssignmentsAreTenantScoped is the reason definitions and assignments
// are two item types: a grant in one tenant must not authorise in another.
func TestRoleAssignmentsAreTenantScoped(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	user := uniqueID("usr")

	for _, r := range []string{"admin", "reader"} {
		if err := store.CreateRole(ctx, r, []string{r + ":act"}); err != nil {
			t.Fatalf("create %s: %v", r, err)
		}
	}
	if err := store.AddRoleToUser(ctx, user, "admin", "acme"); err != nil {
		t.Fatalf("assign in acme: %v", err)
	}
	if err := store.AddRoleToUser(ctx, user, "reader", "globex"); err != nil {
		t.Fatalf("assign in globex: %v", err)
	}

	acme, err := store.GetRolesForUser(ctx, user, "acme")
	if err != nil {
		t.Fatalf("roles in acme: %v", err)
	}
	if fmt.Sprint(acme) != fmt.Sprint([]string{"admin"}) {
		t.Fatalf("roles in acme = %v, want [admin]", acme)
	}
	ok, err := store.UserHasPermission(ctx, user, "reader:act", "acme")
	if err != nil {
		t.Fatalf("permission check: %v", err)
	}
	if ok {
		t.Fatal("a role granted in globex authorised in acme")
	}
}

func TestUserPermissionsAreTheUnionOfTheirRoles(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	user := uniqueID("usr")

	if err := store.CreateRole(ctx, "editor", []string{"post:write", "post:read"}); err != nil {
		t.Fatalf("create editor: %v", err)
	}
	if err := store.CreateRole(ctx, "viewer", []string{"post:read"}); err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	for _, r := range []string{"editor", "viewer"} {
		if err := store.AddRoleToUser(ctx, user, r, "acme"); err != nil {
			t.Fatalf("assign %s: %v", r, err)
		}
	}

	got, err := store.GetPermissionsForUser(ctx, user, "acme")
	if err != nil {
		t.Fatalf("permissions for user: %v", err)
	}
	// Deduplicated and sorted, as MemoryRolesPermissionsStore's is.
	if fmt.Sprint(got) != fmt.Sprint([]string{"post:read", "post:write"}) {
		t.Fatalf("permissions = %v, want the sorted union", got)
	}
}

// TestDeleteRoleSweepsAssignments, and the residue it is allowed to leave.
func TestDeleteRoleSweepsAssignments(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if err := store.CreateRole(ctx, "admin", []string{"user:delete"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	users := []string{uniqueID("usr"), uniqueID("usr"), uniqueID("usr")}
	for _, u := range users {
		if err := store.AddRoleToUser(ctx, u, "admin", "acme"); err != nil {
			t.Fatalf("assign to %s: %v", u, err)
		}
	}

	if err := store.DeleteRole(ctx, "admin"); err != nil {
		t.Fatalf("delete role: %v", err)
	}
	roles, err := store.GetAllRoles(ctx)
	if err != nil {
		t.Fatalf("get all roles: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("definition survived: %v", roles)
	}
	for _, u := range users {
		held, err := store.GetRolesForUser(ctx, u, "acme")
		if err != nil {
			t.Fatalf("roles for %s: %v", u, err)
		}
		if len(held) != 0 {
			t.Fatalf("assignment for %s survived: %v", u, held)
		}
	}

	// A second delete is a no-op, which is what makes the sweep safe to retry.
	if err := store.DeleteRole(ctx, "admin"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

// TestAnAssignmentWithoutADefinitionGrantsNothing is the residue DeleteRole's
// eventually-consistent sweep is allowed to leave. It has to be inert, or the
// sweep would be a security problem rather than a tidy-up.
func TestAnAssignmentWithoutADefinitionGrantsNothing(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	user := uniqueID("usr")

	if err := store.CreateRole(ctx, "admin", []string{"user:delete"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.AddRoleToUser(ctx, user, "admin", "acme"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	perms, err := store.GetPermissionsForUser(ctx, user, "acme")
	if err != nil {
		t.Fatalf("permissions: %v", err)
	}
	if len(perms) != 1 {
		t.Fatalf("sanity check: expected the grant to be live, got %v", perms)
	}

	// Delete only the definition, leaving the assignment behind: the exact state
	// an index that lagged DeleteRole's sweep produces.
	if _, err := client.DeleteItem(ctx, &awsddb.DeleteItemInput{
		TableName: aws.String(store.table),
		Key:       key(rolesPK, roleSK("admin")),
	}); err != nil {
		t.Fatalf("raw delete of the definition: %v", err)
	}

	perms, err = store.GetPermissionsForUser(ctx, user, "acme")
	if err != nil {
		t.Fatalf("permissions after the definition went: %v", err)
	}
	if len(perms) != 0 {
		t.Fatalf("an orphaned assignment still granted %v", perms)
	}
	ok, err := store.UserHasPermission(ctx, user, "user:delete", "acme")
	if err != nil {
		t.Fatalf("permission check: %v", err)
	}
	if ok {
		t.Fatal("an orphaned assignment still authorised")
	}
	// It is still listed, which is the whole of the visible residue.
	held, err := store.GetRolesForUser(ctx, user, "acme")
	if err != nil {
		t.Fatalf("roles: %v", err)
	}
	if fmt.Sprint(held) != fmt.Sprint([]string{"admin"}) {
		t.Fatalf("roles = %v, want the orphan still listed", held)
	}
}
