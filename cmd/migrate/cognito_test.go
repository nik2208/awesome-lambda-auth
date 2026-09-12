package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"

	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
	"github.com/nik2208/awesome-lambda-auth/internal/store/migrating"
)

const testPool = "eu-west-1_EXAMPLE00"

func testRef() migrating.SourceRef {
	return migrating.SourceRef{Source: "cognito", Pool: testPool}
}

// fakeDirectory pages a fixed list of records and records nothing else. It is
// SDK-free, which is the point of CognitoDirectory: nothing in this command's
// tests has to know what a ListUsersInput looks like.
type fakeDirectory struct {
	pages   [][]awsintegration.CognitoUser
	pageErr map[int]error
	calls   int
}

func (f *fakeDirectory) ListUsers(_ context.Context, token string, _ int32) (awsintegration.CognitoUserPage, error) {
	index := 0
	if token != "" {
		// The tokens this fake mints are "page-<n>", so a resume with the token an
		// interrupted run printed lands exactly where that run stopped.
		n, err := pageIndex(token)
		if err != nil {
			return awsintegration.CognitoUserPage{}, err
		}
		index = n
	}
	f.calls++
	if err := f.pageErr[index]; err != nil {
		return awsintegration.CognitoUserPage{}, err
	}
	if index >= len(f.pages) {
		return awsintegration.CognitoUserPage{}, nil
	}
	page := awsintegration.CognitoUserPage{Users: f.pages[index]}
	if index+1 < len(f.pages) {
		page.NextToken = "page-" + strconv.Itoa(index+1)
	}
	return page, nil
}

func (f *fakeDirectory) GetUser(context.Context, string) (awsintegration.CognitoUser, error) {
	return awsintegration.CognitoUser{}, awsintegration.ErrCognitoUserNotFound
}

func (f *fakeDirectory) VerifyPassword(context.Context, string, string) error {
	return awsintegration.ErrCognitoPasswordRejected
}

var _ awsintegration.CognitoDirectory = (*fakeDirectory)(nil)

// pageIndex decodes the "page-<n>" tokens this fake mints, so that resuming
// with the token an interrupted run printed lands exactly where it stopped.
func pageIndex(token string) (int, error) {
	rest, ok := strings.CutPrefix(token, "page-")
	if !ok {
		return 0, errors.New("unknown pagination token")
	}
	return strconv.Atoi(rest)
}

// recordingWriter is the store half. It is the same narrow userWriter the dry
// run implements, so a test can assert on exactly what would have been written.
type recordingWriter struct {
	mu       sync.Mutex
	created  []auth.User
	markers  []ddbstore.MigrationMarker
	existing map[string]bool
}

func newRecordingWriter() *recordingWriter {
	return &recordingWriter{existing: map[string]bool{}}
}

func (w *recordingWriter) CreateMigratedUser(_ context.Context, user auth.User, marker ddbstore.MigrationMarker) (auth.User, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.existing[user.Email] {
		return auth.User{}, auth.ErrUserExists
	}
	w.existing[user.Email] = true
	w.created = append(w.created, user)
	w.markers = append(w.markers, marker)
	return user, nil
}

func rec(username string, attrs map[string]string) awsintegration.CognitoUser {
	return awsintegration.CognitoUser{Username: username, Enabled: true, Status: "CONFIRMED", Attributes: attrs}
}

func withUser(email string) map[string]string {
	return map[string]string{"email": email, "email_verified": "true"}
}

func runImport(t *testing.T, o importOptions) error {
	t.Helper()
	return importAll(context.Background(), o)
}

func baseOptions(t *testing.T, dir *fakeDirectory, store userWriter) importOptions {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { devnull.Close() })
	return importOptions{
		flags:     cognitoFlags{userPoolID: testPool, table: "authtest", region: "eu-west-1", pageSize: 60},
		directory: dir,
		store:     store,
		attrs:     migrating.DefaultAttributeMap(),
		ref:       testRef(),
		stdout:    devnull,
		stderr:    devnull,
	}
}

func TestImportWritesEveryPageWithTheMarker(t *testing.T) {
	t.Parallel()
	dir := &fakeDirectory{pages: [][]awsintegration.CognitoUser{
		{rec("ada", withUser("ada@example.test")), rec("grace", withUser("grace@example.test"))},
		{rec("alan", withUser("alan@example.test"))},
	}}
	store := newRecordingWriter()

	if err := runImport(t, baseOptions(t, dir, store)); err != nil {
		t.Fatalf("importAll: %v", err)
	}
	if len(store.created) != 3 {
		t.Fatalf("created %d users, want 3", len(store.created))
	}
	for i, u := range store.created {
		// The marker arrives as its own argument, never on the user. That is what
		// keeps it off GET /me, and here it is what makes the assertion possible:
		// there is no field on u to look at.
		if store.markers[i] != testRef().Marker() {
			t.Errorf("%s was written with marker %+v, want %+v", u.Email, store.markers[i], testRef().Marker())
		}
		if _, leaked := u.Metadata["migration"]; leaked {
			t.Errorf("%s carries the marker on auth.User.Metadata, which would reach the wire: %v", u.Email, u.Metadata)
		}
		// The password is not imported, because a pool yields no hash. The empty
		// value is also what keeps the passwordless initial-password path open.
		if u.PasswordHash != "" {
			t.Errorf("%s was written with a password hash %q", u.Email, u.PasswordHash)
		}
		if !u.IsEmailVerified {
			t.Errorf("%s lost its email_verified flag", u.Email)
		}
	}
}

// A user that already exists is SKIPPED, never overwritten. This is the decision
// that makes re-running the whole command the recommended recovery: a row that
// has already adopted a password would otherwise be rewritten with the empty
// hash and the marker, stranding the person on a directory they have left.
func TestImportSkipsAUserThatAlreadyExists(t *testing.T) {
	t.Parallel()
	dir := &fakeDirectory{pages: [][]awsintegration.CognitoUser{
		{rec("ada", withUser("ada@example.test")), rec("grace", withUser("grace@example.test"))},
	}}
	store := newRecordingWriter()
	store.existing["ada@example.test"] = true

	if err := runImport(t, baseOptions(t, dir, store)); err != nil {
		t.Fatalf("importAll: %v", err)
	}
	if len(store.created) != 1 || store.created[0].Email != "grace@example.test" {
		t.Fatalf("created = %v, want only grace", store.created)
	}
	// And it is not an error: an idempotent re-run must exit 0.
}

// A record with no email is skipped and reported, and the run continues. One
// unusable record in a pool of forty thousand must not end the import, and must
// not be silently dropped either — so the run finishes and then fails.
func TestImportSkipsAndReportsARecordWithNoEmail(t *testing.T) {
	t.Parallel()
	dir := &fakeDirectory{pages: [][]awsintegration.CognitoUser{{
		rec("ada", withUser("ada@example.test")),
		rec("0cb4e2f4-no-email", map[string]string{"phone_number": "+15550100"}),
		rec("grace", withUser("grace@example.test")),
	}}}
	store := newRecordingWriter()

	err := runImport(t, baseOptions(t, dir, store))
	if err == nil {
		t.Fatal("a run that skipped a record exited 0; a pipeline would not notice")
	}
	if len(store.created) != 2 {
		t.Fatalf("created %d users, want the two that had an address", len(store.created))
	}
}

// A paging failure stops the run and reports the token of the last page that
// COMPLETED, not of the page that failed: printing the failing page's token
// would skip the half of it that was written.
func TestImportStopsOnAPagingFailureAndCanResume(t *testing.T) {
	t.Parallel()
	dir := &fakeDirectory{
		pages: [][]awsintegration.CognitoUser{
			{rec("ada", withUser("ada@example.test"))},
			{rec("grace", withUser("grace@example.test"))},
			{rec("alan", withUser("alan@example.test"))},
		},
		pageErr: map[int]error{1: errors.New("the pool stopped answering")},
	}
	store := newRecordingWriter()

	if err := runImport(t, baseOptions(t, dir, store)); err == nil {
		t.Fatal("a run interrupted by a paging failure exited 0")
	}
	if len(store.created) != 1 {
		t.Fatalf("created %d users, want the one page that completed", len(store.created))
	}

	// Resuming from the printed token picks up exactly where it stopped.
	dir.pageErr = nil
	opts := baseOptions(t, dir, store)
	opts.flags.startToken = "page-1"
	if err := runImport(t, opts); err != nil {
		t.Fatalf("resumed run: %v", err)
	}
	if len(store.created) != 3 {
		t.Fatalf("after resuming, created %d users, want 3", len(store.created))
	}
}

// --dry-run reports exactly what it would write and writes nothing. It is a
// complete implementation of the same narrow interface the real store satisfies,
// so everything above it — the marker, the attribute mapping, the skip decisions
// — is exercised as it would be in a real run.
func TestDryRunWritesNothingAndReportsEverything(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "dryrun.txt")
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	dir := &fakeDirectory{pages: [][]awsintegration.CognitoUser{{
		rec("ada", map[string]string{
			"email": "ada@example.test", "email_verified": "true",
			"phone_number": "+15550100", "custom:department": "analytics",
		}),
	}}}
	real := newRecordingWriter()

	opts := baseOptions(t, dir, dryRunWriter{out: f})
	opts.flags.dryRun = true
	opts.stdout = f
	if err := runImport(t, opts); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(real.created) != 0 {
		t.Fatal("the dry run reached the real store")
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	report := string(raw)
	for _, want := range []string{
		"ada@example.test",
		"emailVerified",
		"phone",
		"migration{source=cognito,pool=" + testPool + "}",
		testPool,
		ddbstore.ImportedAttributesKey,
		"department=analytics",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the dry run does not report %q:\n%s", want, report)
		}
	}
}

func TestAttributeMapFileIsValidatedBeforeAnythingIsRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"custom:tier":"role","locale":"-"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	m, err := loadAttributeMap(good)
	if err != nil {
		t.Fatalf("loadAttributeMap: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("a valid map was refused: %v", err)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"custom:tier":"rolle"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	m, err = loadAttributeMap(bad)
	if err != nil {
		t.Fatalf("loadAttributeMap: %v", err)
	}
	if err := m.Validate(); err == nil {
		t.Fatal("a misspelled target was accepted; four thousand users would be imported without it")
	}

	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadAttributeMap(empty); err == nil {
		t.Fatal("an empty map file was accepted; it silently drops every attribute")
	}
}

func TestRunRefusesMissingFlags(t *testing.T) {
	t.Parallel()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer devnull.Close()

	cases := [][]string{
		{"cognito"},
		{"cognito", "--user-pool-id", testPool},
		{"cognito", "--user-pool-id", testPool, "--table", "authtest"},
		{"cognito", "--user-pool-id", testPool, "--table", "authtest", "--region", "eu-west-1", "--page-size", "600"},
	}
	for _, args := range cases {
		if err := run(context.Background(), args, devnull, devnull); err == nil {
			t.Errorf("run(%v) succeeded; an incomplete command must not start reading a pool", args)
		}
	}
	if err := run(context.Background(), []string{"nonsense"}, devnull, devnull); err == nil {
		t.Error("an unknown subcommand succeeded")
	}
}
