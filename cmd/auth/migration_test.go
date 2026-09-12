package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
	"github.com/nik2208/awesome-lambda-auth/internal/store/migrating"
)

const (
	migrationPool     = "eu-west-1_EXAMPLE00"
	migrationClientID = "exampleappclientid00000000"
)

// fakeDirectory is the CognitoDirectory these tests inject through
// Options.Cognito. It is SDK-free, which is why this package's tests never
// import the AWS SDK for it.
type fakeDirectory struct {
	mu        sync.Mutex
	passwords map[string]string
	users     map[string]awsintegration.CognitoUser
	verifyErr error
	verifies  int
}

func newFakeDirectory() *fakeDirectory {
	return &fakeDirectory{passwords: map[string]string{}, users: map[string]awsintegration.CognitoUser{}}
}

func (f *fakeDirectory) ListUsers(context.Context, string, int32) (awsintegration.CognitoUserPage, error) {
	return awsintegration.CognitoUserPage{}, nil
}

func (f *fakeDirectory) GetUser(_ context.Context, username string) (awsintegration.CognitoUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[username]
	if !ok {
		return awsintegration.CognitoUser{}, awsintegration.ErrCognitoUserNotFound
	}
	return u, nil
}

func (f *fakeDirectory) VerifyPassword(_ context.Context, username, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies++
	if f.verifyErr != nil {
		return f.verifyErr
	}
	if want, ok := f.passwords[username]; ok && want == password {
		return nil
	}
	return awsintegration.ErrCognitoPasswordRejected
}

func (f *fakeDirectory) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verifies
}

var _ awsintegration.CognitoDirectory = (*fakeDirectory)(nil)

// migrationEnv turns the block on over whatever base is given.
func migrationEnv(base map[string]string, extra ...string) map[string]string {
	return with(base, append([]string{
		"AWESOME_AUTH_STORES_MIGRATION_SOURCE", config.MigrationSourceCognito,
		"AWESOME_AUTH_STORES_MIGRATION_USER_POOL_ID", migrationPool,
		"AWESOME_AUTH_STORES_MIGRATION_REGION", "eu-west-1",
		"AWESOME_AUTH_STORES_MIGRATION_CLIENT_ID", migrationClientID,
	}, extra...)...)
}

// TestMigrationBlockRefusesTheMemoryDriver pins RS-13's capability clause from
// the outside: the marker is a DynamoDB profile attribute and there is nowhere
// else in this build it survives a cold start.
func TestMigrationBlockRefusesTheMemoryDriver(t *testing.T) {
	t.Parallel()
	_, err := New(context.Background(), Options{
		Getenv:  envFunc(migrationEnv(baseEnv())),
		Logger:  discardLogger(),
		Stores:  memoryStores,
		Cognito: newFakeDirectory(),
	})
	if err == nil {
		t.Fatal("a migration block on the memory driver was accepted")
	}
	var verr *config.ValidationError
	if !errors.As(err, &verr) || !verr.HasRule(config.RuleMigrationIncomplete) {
		t.Fatalf("error = %v, want the %s rule to have fired", err, config.RuleMigrationIncomplete)
	}
}

// An unconfigured block constructs nothing and wires nothing, which is what
// makes every deployment that is not migrating bit-for-bit the one that shipped
// before this block existed.
func TestNoMigrationBlockWiresNothing(t *testing.T) {
	t.Parallel()
	users := newMemoryStoreBundle()
	cfg := config.Defaults()

	got, err := migrationWiring(cfg, users, newFakeDirectory(), discardLogger())
	if err != nil {
		t.Fatalf("migrationWiring: %v", err)
	}
	if _, wrapped := got.(*migrating.MigratingUserStore); wrapped {
		t.Error("an unconfigured block wrapped the user store")
	}

	opts, err := migrationOptions(cfg, got)
	if err != nil {
		t.Fatalf("migrationOptions: %v", err)
	}
	if len(opts) != 0 {
		t.Errorf("an unconfigured block contributed %d core option(s)", len(opts))
	}
}

// migrationFixture is one app on DynamoDB Local, with or without the migration
// block, plus the directory behind it.
type migrationFixture struct {
	app   *App
	dir   *fakeDirectory
	store *ddbstore.Store
	table string
}

// newMigrationFixture builds an app against DynamoDB Local. It cannot be
// parallel: the AWS SDK reads credentials from the environment and t.Setenv
// forbids parallel tests, which is the same constraint
// TestDynamoDBBackedRoutesFindEveryStore works under.
func newMigrationFixture(t *testing.T, withMigration bool, extra ...string) migrationFixture {
	t.Helper()
	endpoint, ok := localDynamoDBEndpoint()
	if !ok {
		t.Skip("DYNAMODB_ENDPOINT is not set; start DynamoDB Local and set it to run this end-to-end test")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_REGION", "us-east-1")

	ctx := context.Background()
	table := "authtest_migration_" + randomSuffix(t)
	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{Region: "us-east-1", Endpoint: endpoint})
	if err != nil {
		t.Skipf("cannot build a DynamoDB client for %s: %v", endpoint, err)
	}
	if err := ddbstore.CreateTable(ctx, client, table); err != nil {
		t.Skipf("cannot create %s at %s (%v); start DynamoDB Local with: "+
			"docker run -d --name ddblocal -p 8000:8000 amazon/dynamodb-local", table, endpoint, err)
	}

	env := with(baseEnv(),
		"AWESOME_AUTH_STORES_DRIVER", config.StoreDriverDynamoDB,
		"AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", table,
		"AWESOME_AUTH_STORES_CONNECTION_REGION", "us-east-1",
		"AWESOME_AUTH_STORES_CONNECTION_ENDPOINT", endpoint,
		// The product's own rate limiter is off here, and only here. It is on by
		// default and these tests deliberately drive one address past ten
		// attempts in a minute — TestLoginIsByteIdenticalWithAVerifierConfigured
		// spends the *migration* limiter's budget on purpose, to prove that its
		// refusal is indistinguishable from a wrong password. With both limiters
		// running, the two deployments answer differently for a reason that has
		// nothing to do with the verifier: the migrating one has made twelve more
		// requests against that address than the plain one and is refused 429
		// where the plain one is still answering 401. That is the product limiter
		// working, not the seam leaking, and leaving it on would make this file
		// assert the opposite of what it says.
		//
		// What the product limiter does on the wire is rate-limited-routes-answer-429
		// in the register, and it is exercised by cmd/auth/ratelimit_test.go and by
		// the opt-in contract case. Nothing about it is untested by being off here.
		"AWESOME_AUTH_RATE_LIMIT_ENABLED", "false",
	)
	if withMigration {
		env = migrationEnv(env, extra...)
	}

	dir := newFakeDirectory()
	app, err := New(ctx, Options{Getenv: envFunc(env), Logger: discardLogger(), Cognito: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	store, err := ddbstore.New(client, ddbstore.Options{TableName: table, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("ddbstore.New: %v", err)
	}
	return migrationFixture{app: app, dir: dir, store: store, table: table}
}

// migrationRef is what this fixture's markers name.
func migrationRef() migrating.SourceRef {
	return migrating.SourceRef{Source: config.MigrationSourceCognito, Pool: migrationPool}
}

// stillMarked reports whether the profile still carries a marker. It has to go
// through the carrier, because there is nowhere else a marker can be observed —
// which is the property TestMigrationDisclosesNothingOnTheWire exists to defend.
func stillMarked(t *testing.T, f migrationFixture, userID string) bool {
	t.Helper()
	ctx := ddbstore.WithMigrationScope(context.Background())
	if _, err := f.store.GetUserByID(ctx, userID, ""); err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	marker, ok := ddbstore.TakeMigrationMarker(ctx, userID)
	if !ok {
		t.Fatal("the profile read filed nothing")
	}
	return !marker.IsZero()
}

// seedImported writes the row cmd/migrate would have written: a real address, an
// empty password hash, and the marker — which is an argument and not a field,
// because it never rides on auth.User.
func (f migrationFixture) seedImported(t *testing.T, email string) auth.User {
	t.Helper()
	return f.seedImportedWith(t, f.seedImportedUser(t, email))
}

func (f migrationFixture) seedImportedWith(t *testing.T, user auth.User) auth.User {
	t.Helper()
	created, err := f.store.CreateMigratedUser(context.Background(), user, migrationRef().Marker())
	if err != nil {
		t.Fatalf("seed imported row: %v", err)
	}
	return created
}

// seedImportedUser builds that row without writing it, for the one test that has
// to adjust it first.
func (f migrationFixture) seedImportedUser(t *testing.T, email string) auth.User {
	t.Helper()
	id, err := migrating.NewUserID()
	if err != nil {
		t.Fatalf("NewUserID: %v", err)
	}
	return auth.User{
		ID:              id,
		Email:           email,
		IsEmailVerified: true,
		// Something in metadata, so the disclosure test is checking that the
		// MARKER is absent rather than that metadata happens to be empty.
		Metadata: map[string]any{ddbstore.ImportedAttributesKey: map[string]any{"department": "analytics"}},
	}
}

func loginBody(email, password string) string {
	raw, _ := json.Marshal(map[string]string{"email": email, "password": password})
	return string(raw)
}

// TestLoginIsByteIdenticalWithAVerifierConfigured is the property the upstream
// seam demands and this product must not break: with a verifier configured,
// POST /login answers exactly what it answered before — same status, same code,
// same body — and a client cannot tell the two deployments apart.
//
// Upstream states it as a requirement and says that anything a client could use
// to tell a configured verifier apart is a wire deviation that would have to be
// registered. Nothing here is registered, so this test is what keeps the claim
// true rather than merely intended.
//
// Four requests, chosen because each is a different way into the verifier:
//
//   - an address neither deployment holds, which never reaches the hook at all;
//   - an ordinary local account with a wrong password, which reaches the hook
//     and is turned away by the marker gate;
//   - an IMPORTED account with a wrong password, which reaches the hook, passes
//     the gate, asks the directory and is refused by it;
//   - an imported account whose rate limit is spent, which passes the gate and
//     is refused without a call.
//
// The last two are the interesting ones: they are the paths that exist only in
// the migrating deployment, and their answers must be indistinguishable from the
// second, which exists in both.
func TestLoginIsByteIdenticalWithAVerifierConfigured(t *testing.T) {
	plain := newMigrationFixture(t, false)
	migrated := newMigrationFixture(t, true)

	const (
		local    = "local@example.test"
		imported = "imported@example.test"
		unknown  = "unknown@example.test"
	)

	// The same ordinary account exists in both, registered the same way.
	for _, f := range []migrationFixture{plain, migrated} {
		if resp := invoke(t, f.app, http.MethodPost, "/auth/register",
			jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
			registerBody(local)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("register status = %d (body %s)", resp.StatusCode, resp.Body)
		}
	}

	// The imported row exists in both too, so that the only difference between
	// the two deployments is whether a verifier is wired — not what the table
	// holds. In the plain deployment the marker is inert data on a row with an
	// empty hash, which is exactly what it would be on a stack that imported
	// users and then turned the block off.
	plain.seedImported(t, imported)
	migrated.seedImported(t, imported)
	migrated.dir.passwords[imported] = "the old password"

	requests := []struct {
		name string
		body string
	}{
		{"an address neither deployment holds", loginBody(unknown, "whatever")},
		{"an ordinary account, wrong password", loginBody(local, "not the password")},
		{"an imported account, wrong password", loginBody(imported, "not the password")},
	}

	for _, tc := range requests {
		a := invoke(t, plain.app, http.MethodPost, "/auth/login",
			jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, tc.body)
		b := invoke(t, migrated.app, http.MethodPost, "/auth/login",
			jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, tc.body)

		if got, want := renderAnswer(a), renderAnswer(b); got != want {
			t.Errorf("%s: the two deployments answer differently.\nwithout a verifier: %s\nwith a verifier:    %s",
				tc.name, got, want)
		}
	}

	// And the limiter, which is the other path that exists only in the migrating
	// deployment. Spend the budget on wrong passwords, then check that a refused
	// call still answers what a wrong password answers.
	before := migrated.dir.calls()
	body := loginBody(imported, "still not the password")
	for range 12 {
		invoke(t, migrated.app, http.MethodPost, "/auth/login",
			jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, body)
	}
	if after := migrated.dir.calls(); after-before >= 12 {
		t.Errorf("the directory was called %d times for 12 logins; the verifier is not bounded", after-before)
	}

	a := invoke(t, plain.app, http.MethodPost, "/auth/login",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, body)
	b := invoke(t, migrated.app, http.MethodPost, "/auth/login",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, body)
	if got, want := renderAnswer(a), renderAnswer(b); got != want {
		t.Errorf("a rate-limited login is distinguishable from a wrong password.\nwithout a verifier: %s\nwith a verifier:    %s", got, want)
	}
}

// TestMigratedLoginSucceedsAndAdoptsThePassword is the other half: the seam has
// to actually work, not merely be invisible.
func TestMigratedLoginSucceedsAndAdoptsThePassword(t *testing.T) {
	f := newMigrationFixture(t, true)
	const (
		email    = "ada@example.test"
		password = "the old password"
	)
	f.seedImported(t, email)
	f.dir.passwords[email] = password

	resp := invoke(t, f.app, http.MethodPost, "/auth/login",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, loginBody(email, password))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200 (body %s)", resp.StatusCode, resp.Body)
	}
	if token, _ := decodeBody(t, resp)["accessToken"].(string); token == "" {
		t.Fatalf("the migrated login issued no access token: %s", resp.Body)
	}

	// The migration ended for this person: the marker is gone and the next login
	// does not consult the directory.
	after, err := f.store.GetUserByEmail(context.Background(), email, "")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stillMarked(t, f, after.ID) {
		t.Error("the marker survived adoption")
	}
	before := f.dir.calls()
	if resp := invoke(t, f.app, http.MethodPost, "/auth/login",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		loginBody(email, password)); resp.StatusCode != http.StatusOK {
		t.Fatalf("second login status = %d (body %s)", resp.StatusCode, resp.Body)
	}
	if got := f.dir.calls(); got != before {
		t.Errorf("the directory was consulted %d more times after adoption", got-before)
	}
}

// TestAnAccountWithNoMarkerNeverReachesTheSource drives the gate through the
// real route rather than through the verifier directly, because that is where
// the accounts the gate exists for actually arrive: an OAuth-only or
// magic-link-only account carries an empty hash, so its failed logins reach the
// hook carrying whatever plaintext the request held.
func TestAnAccountWithNoMarkerNeverReachesTheSource(t *testing.T) {
	f := newMigrationFixture(t, true)

	// A registered account with a password, and a passwordless one: the two
	// shapes that reach the hook without a marker.
	const registered = "registered@example.test"
	if resp := invoke(t, f.app, http.MethodPost, "/auth/register",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		registerBody(registered)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d (body %s)", resp.StatusCode, resp.Body)
	}

	const passwordless = "oauth-only@example.test"
	id, err := migrating.NewUserID()
	if err != nil {
		t.Fatalf("NewUserID: %v", err)
	}
	if _, err := f.store.CreateUser(context.Background(), auth.User{
		ID: id, Email: passwordless, IsEmailVerified: true, LoginProvider: "google",
	}); err != nil {
		t.Fatalf("seed the passwordless account: %v", err)
	}
	f.dir.passwords[registered] = "anything"
	f.dir.passwords[passwordless] = "anything"

	for _, email := range []string{registered, passwordless} {
		resp := invoke(t, f.app, http.MethodPost, "/auth/login",
			jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, loginBody(email, "anything"))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: login status = %d, want 401 (body %s)", email, resp.StatusCode, resp.Body)
		}
	}
	if got := f.dir.calls(); got != 0 {
		t.Fatalf("the source was asked %d times about accounts with no marker; "+
			"an unauthenticated route that forwards any address it is handed is an amplifier", got)
	}
}

// TestMigrationDisclosesNothingOnTheWire is why this block registers no
// deviation.
//
// The marker could not live on auth.User: auth.NewPublicUser serialises
// Metadata and GET <prefix>/me is that projection unwrapped, so a marker there
// would name the source directory and the user pool id to whoever holds a
// session on a not-yet-migrated account. It lives on the request context
// instead (internal/store/dynamodb/migration.go), and this is the test that the
// separation actually holds end to end, through the deployed composition rather
// than through the store's own unit tests.
//
// GET /me is the route that matters, and it is the only one: POST /login and
// /register answer a token pair and a success flag, and nothing else in the
// adapter writes a PublicUser.
//
// The account is built with the marker AND a working local hash, which is how an
// imported account that reached a session without adopting looks — through a
// magic link or an SMS code, the two ways to be signed in without presenting a
// password. That is the state in which a marker would have been visible, so it
// is the state worth checking. The hash is taken from a registered account
// rather than synthesised, so the two users share a password and no bcrypt
// dependency is added here.
func TestMigrationDisclosesNothingOnTheWire(t *testing.T) {
	f := newMigrationFixture(t, true)
	const donor = "donor@example.test"
	if resp := invoke(t, f.app, http.MethodPost, "/auth/register",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		registerBody(donor)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d (body %s)", resp.StatusCode, resp.Body)
	}
	seed, err := f.store.GetUserByEmail(context.Background(), donor, "")
	if err != nil {
		t.Fatalf("read the donor hash: %v", err)
	}

	const marked = "visible@example.test"
	user := f.seedImportedUser(t, marked)
	user.PasswordHash = seed.PasswordHash
	f.seedImportedWith(t, user)

	resp := invoke(t, f.app, http.MethodPost, "/auth/login",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, loginBody(marked, testPassword))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d (body %s)", resp.StatusCode, resp.Body)
	}
	token, _ := decodeBody(t, resp)["accessToken"].(string)
	if token == "" {
		t.Fatalf("no access token: %s", resp.Body)
	}

	me := invoke(t, f.app, http.MethodGet, "/auth/me", map[string]string{"authorization": "Bearer " + token}, nil, "")
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me status = %d (body %s)", me.StatusCode, me.Body)
	}
	// Neither the pool id nor the marker key, anywhere in the body. If this ever
	// fails, the marker has found its way back onto auth.User and the deviation
	// it used to require has to come back with it.
	for _, forbidden := range []string{migrationPool, `"migration"`, config.MigrationSourceCognito} {
		if strings.Contains(me.Body, forbidden) {
			t.Errorf("GET /me discloses %q for a migrating account: %s", forbidden, me.Body)
		}
	}
	// And the login response, which carries no user object at all today but is
	// the obvious place for one to be added.
	if strings.Contains(resp.Body, migrationPool) {
		t.Errorf("the login response discloses the pool id: %s", resp.Body)
	}

	// The operator's own imported data IS on the wire, deliberately and
	// documented: it is data about the person, in the field the reference
	// defines for exactly that, and opt-out per attribute in the map.
	if !strings.Contains(me.Body, "analytics") {
		t.Errorf("the imported attributes did not reach GET /me; §13 of the config reference says they do: %s", me.Body)
	}
}

// renderAnswer is everything about a login response a client can observe,
// rendered as one comparable string: the status, the sorted headers, the sorted
// cookies and the body verbatim.
//
// Nothing is filtered out. These are the failure answers, and none of them
// carries a token, a timestamp or anything else that varies between two
// identical requests — which is itself part of what is being asserted: a body
// that differed run to run would make this test pass by being unable to see
// anything.
func renderAnswer(resp events.APIGatewayV2HTTPResponse) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(resp.StatusCode))

	names := make([]string, 0, len(resp.Headers))
	for name := range resp.Headers {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	for _, name := range names {
		b.WriteString("\n" + name + ": " + resp.Headers[name])
	}

	cookies := append([]string(nil), resp.Cookies...)
	sort.Strings(cookies)
	for _, c := range cookies {
		b.WriteString("\nset-cookie: " + c)
	}

	b.WriteString("\n\n" + resp.Body)
	return b.String()
}
