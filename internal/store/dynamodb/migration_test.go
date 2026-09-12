package dynamodb

import (
	"context"
	"sync"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

const testMigrationPool = "eu-west-1_EXAMPLE00"

func testMarker() MigrationMarker {
	return MigrationMarker{Source: "cognito", Pool: testMigrationPool}
}

// stillMarked reports whether the profile still carries a marker, read the only
// way anything can read one: a profile read on a scoped context, followed by a
// take. That the assertion has to go through the carrier is itself the property
// under test — there is no field on auth.User to look at any more.
func stillMarked(t *testing.T, store *Store, userID string) bool {
	t.Helper()
	ctx := WithMigrationScope(context.Background())
	if _, err := store.GetUserByID(ctx, userID, ""); err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	marker, ok := TakeMigrationMarker(ctx, userID)
	if !ok {
		t.Fatal("the profile read filed nothing")
	}
	return !marker.IsZero()
}

// importedUser is the row cmd/migrate writes: a real address, an EMPTY password
// hash — a user pool yields none — and the imported attributes. The marker is
// NOT on it: it is a separate argument to CreateMigratedUser, which is what
// keeps it off auth.User in both directions.
func importedUser(email string) auth.User {
	return auth.User{
		ID:              uniqueID("usr"),
		Email:           email,
		IsEmailVerified: true,
		Metadata:        map[string]any{ImportedAttributesKey: map[string]any{"department": "analytics"}},
	}
}

// The marker reaches the verifier through the request-scoped carrier and never
// through auth.User. This is the whole mechanism, end to end: one profile read
// files it, a take by user id returns it, and the returned auth.User carries no
// trace of it.
func TestMigrationMarkerTravelsOnTheContextNotTheUser(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	email := uniqueEmail("imported")

	ctx := WithMigrationScope(context.Background())
	created, err := store.CreateMigratedUser(ctx, importedUser(email), testMarker())
	if err != nil {
		t.Fatalf("CreateMigratedUser: %v", err)
	}
	// CreateMigratedUser files it too, because the dual-read path creates a row
	// and hands it straight to the verifier with no intervening read.
	if marker, ok := TakeMigrationMarker(ctx, created.ID); !ok || marker != testMarker() {
		t.Errorf("after a create, TakeMigrationMarker = (%v, %v), want the written marker", marker, ok)
	}

	// And the ordinary path: one profile read files it.
	read := WithMigrationScope(context.Background())
	got, err := store.GetUserByEmail(read, email, "")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	marker, ok := TakeMigrationMarker(read, got.ID)
	if !ok {
		t.Fatal("the profile read filed nothing; the verifier would fail closed and nobody would migrate")
	}
	if marker != testMarker() {
		t.Errorf("marker = %+v, want %+v", marker, testMarker())
	}

	// The user the store returned carries nothing about the migration. This is
	// the property that retires the disclosure: auth.NewPublicUser serialises
	// Metadata, so anything here would be on GET /me.
	if _, leaked := got.Metadata["migration"]; leaked {
		t.Errorf("the marker is on auth.User.Metadata and would reach the wire: %v", got.Metadata)
	}
	for k, v := range got.Metadata {
		if k != ImportedAttributesKey {
			t.Errorf("unexpected metadata key %q = %v", k, v)
		}
	}
	imported, ok := got.Metadata[ImportedAttributesKey].(map[string]any)
	if !ok || imported["department"] != "analytics" {
		t.Errorf("imported attributes = %v", got.Metadata[ImportedAttributesKey])
	}
	if got.PasswordHash != "" {
		t.Errorf("PasswordHash = %q, want empty: a user pool yields no hash to import", got.PasswordHash)
	}
}

// The carrier is single-slot and id-keyed, like rotationScope: a record from one
// user's read must never answer for another's, and a take consumes it so a
// second verifier call in one request re-reads rather than reusing.
func TestMigrationScopeIsKeyedAndConsumed(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	email := uniqueEmail("keyed")

	ctx := WithMigrationScope(context.Background())
	created, err := store.CreateMigratedUser(ctx, importedUser(email), testMarker())
	if err != nil {
		t.Fatalf("CreateMigratedUser: %v", err)
	}

	if _, ok := TakeMigrationMarker(ctx, "usr_somebody_else"); ok {
		t.Error("a take for another user id succeeded; one user's marker must never answer for another's")
	}
	if _, ok := TakeMigrationMarker(ctx, created.ID); !ok {
		t.Fatal("the first take for the right id failed")
	}
	if _, ok := TakeMigrationMarker(ctx, created.ID); ok {
		t.Error("a second take succeeded; the record must be consumed so a later call re-reads")
	}
}

// With no scope on the context the take reports "nothing recorded", which is
// what makes the verifier fail closed instead of falling back to auth.User.
func TestMigrationScopeAbsentReportsNothingRecorded(t *testing.T) {
	t.Parallel()
	if _, ok := TakeMigrationMarker(context.Background(), "usr_anyone"); ok {
		t.Fatal("a take with no scope reported a record")
	}
}

// An ordinary account records "read, and there is none" — which is a different
// answer from "never read", and only the second is a wiring fault.
func TestAnOrdinaryAccountRecordsAnAbsentMarker(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	email := uniqueEmail("ordinary-marker")

	ctx := WithMigrationScope(context.Background())
	created, err := store.CreateUser(ctx, auth.User{ID: uniqueID("usr"), Email: email, PasswordHash: "hashed"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := store.GetUserByID(ctx, created.ID, ""); err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	marker, ok := TakeMigrationMarker(ctx, created.ID)
	if !ok {
		t.Fatal("an ordinary profile read filed nothing; the verifier could not tell it from a missing scope")
	}
	if !marker.IsZero() {
		t.Errorf("marker = %+v, want the zero value", marker)
	}
}

// Metadata stays nil for a user without a marker, which after a migration is
// every user. The exception the codec makes must be narrow enough that an
// ordinary account is unchanged by it.
func TestAnOrdinaryUserStillHasNilMetadata(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	email := uniqueEmail("ordinary")

	if _, err := store.CreateUser(context.Background(), auth.User{
		ID: uniqueID("usr"), Email: email, PasswordHash: "hashed",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := store.GetUserByEmail(context.Background(), email, "")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got.Metadata != nil {
		t.Errorf("Metadata = %v, want nil for a user with no marker", got.Metadata)
	}
}

// Only the reserved keys are persisted. Round-tripping the whole map would put
// an unbounded, caller-supplied document on the item every login reads, and
// would become this driver's implementation of UserMetadataStore without any of
// that interface's semantics.
func TestOnlyTheReservedMetadataKeysArePersisted(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	email := uniqueEmail("extra")

	if _, err := store.CreateUser(context.Background(), auth.User{
		ID: uniqueID("usr"), Email: email,
		Metadata: map[string]any{
			ImportedAttributesKey: map[string]any{"department": "analytics"},
			"somethingElse":       map[string]any{"a": "b"},
			"aScalar":             "value",
			// A caller cannot smuggle the marker in through Metadata: there is no
			// reserved key for it, so this is dropped like any other stranger.
			"migration": map[string]any{"source": "cognito", "pool": testMigrationPool},
		},
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := store.GetUserByEmail(context.Background(), email, "")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	for _, key := range []string{"somethingElse", "aScalar", "migration"} {
		if _, leaked := got.Metadata[key]; leaked {
			t.Errorf("the unreserved metadata key %q was persisted", key)
		}
	}
	if _, ok := got.Metadata[ImportedAttributesKey]; !ok {
		t.Error("the imported attributes were dropped along with the rest")
	}
}

// An empty marker is not written. The omission rule in §5 is what lets the
// REMOVE in UpdatePassword and an attribute_not_exists condition mean what they
// say, and a present-but-empty marker would be a row that reads as mid-migration
// forever while naming no directory to ask.
func TestAnEmptyMarkerIsNotWritten(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	email := uniqueEmail("emptymarker")

	ctx := WithMigrationScope(context.Background())
	created, err := store.CreateMigratedUser(ctx, auth.User{ID: uniqueID("usr"), Email: email}, MigrationMarker{})
	if err != nil {
		t.Fatalf("CreateMigratedUser: %v", err)
	}
	// Nothing was written, so a fresh read files the zero marker rather than a
	// row that reads as mid-migration forever.
	read := WithMigrationScope(context.Background())
	if _, err := store.GetUserByID(read, created.ID, ""); err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if marker, ok := TakeMigrationMarker(read, created.ID); !ok || !marker.IsZero() {
		t.Errorf("marker = (%+v, %v), want the zero value", marker, ok)
	}

	got, err := store.GetUserByEmail(context.Background(), email, "")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got.Metadata != nil {
		t.Errorf("Metadata = %v, want nil: a marker with no usable field is not a marker", got.Metadata)
	}
}

// UpdatePassword is the write that ends a migration, and it is ONE write. Every
// upstream caller of it — ResetPassword, ChangePassword and the password
// verifier's adoption step — means the same thing about the account: there is a
// local credential now, and the old directory has nothing left to say about it.
func TestUpdatePasswordDropsTheMarker(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	email := uniqueEmail("adopting")

	user, err := store.CreateMigratedUser(context.Background(), importedUser(email), testMarker())
	if err != nil {
		t.Fatalf("CreateMigratedUser: %v", err)
	}
	if err := store.UpdatePassword(context.Background(), user.ID, "", "the-adopted-hash"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}

	got, err := store.GetUserByEmail(context.Background(), email, "")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if stillMarked(t, store, user.ID) {
		t.Error("the marker survived the write that stored a local password; every failed login would keep asking the old directory")
	}
	if got.PasswordHash != "the-adopted-hash" {
		t.Errorf("PasswordHash = %q", got.PasswordHash)
	}
	// The imported attributes are NOT dropped: they are a record of what the old
	// directory held, not a statement about where the credential lives.
	if imported, ok := got.Metadata[ImportedAttributesKey].(map[string]any); !ok || imported["department"] != "analytics" {
		t.Errorf("the imported attributes were dropped with the marker: %v", got.Metadata)
	}
}

// The marker-flip race, against DynamoDB Local because that is the only place
// the question is real.
//
// Adoption is IDEMPOTENT rather than exclusive: several concurrent adopters all
// succeed, each writing a valid hash of the same proven password, and the last
// one wins. What must never happen is the interleaving in which the marker is
// gone while the hash is still the imported empty one — that account would have
// no way back in, because an empty hash verifies nothing and a missing marker
// makes the verifier answer no. Setting the hash and dropping the marker being
// one atomic UpdateItem is what rules it out.
func TestConcurrentPasswordAdoption(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	email := uniqueEmail("racing")

	user, err := store.CreateMigratedUser(context.Background(), importedUser(email), testMarker())
	if err != nil {
		t.Fatalf("CreateMigratedUser: %v", err)
	}

	const racers = 8
	hashes := make([]string, racers)
	for i := range hashes {
		hashes[i] = "hash-" + randomHex(8)
	}

	var wg sync.WaitGroup
	errs := make([]error, racers)
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = store.UpdatePassword(context.Background(), user.ID, "", hashes[i])
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("adopter %d failed: %v; adoption is idempotent, not exclusive -- a loser that errors is a "+
				"generic 500 for a login whose password was correct", i, err)
		}
	}

	got, err := store.GetUserByEmail(context.Background(), email, "")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if stillMarked(t, store, user.ID) {
		t.Fatal("the marker survived a concurrent adoption")
	}
	// Exactly one of the racers' hashes is stored, and it is a whole one: the
	// write is atomic, so no interleaving can leave the hash from one adopter
	// with the marker state of another.
	var matched bool
	for _, h := range hashes {
		if got.PasswordHash == h {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("PasswordHash = %q, which is none of the racers' hashes", got.PasswordHash)
	}
}
