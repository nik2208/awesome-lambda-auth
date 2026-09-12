package migrating

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// The tests that need a store run against DynamoDB Local, for the reason the
// DynamoDB store's own harness gives: what is being tested here is the
// behaviour of a conditional write under concurrency, and a hand-written fake
// would only encode the author's belief about what DynamoDB does. The
// marker-flip race in particular is meaningless against a mutex.
//
// The skip message is worded to match internal/store/dynamodb's, because the
// product gate greps for it: a skipped DynamoDB Local test is a gate FAILURE,
// not a pass (.tools/gate-lambda.sh).
const defaultLocalEndpoint = "http://localhost:8000"

func localEndpoint() string {
	if ep := os.Getenv("DYNAMODB_ENDPOINT"); ep != "" {
		return ep
	}
	return defaultLocalEndpoint
}

type localCredentials struct{}

func (localCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "local", SecretAccessKey: "local", Source: "dynamodb-local-test"}, nil
}

var (
	probeOnce sync.Once
	probeErr  error
)

func testClient(t *testing.T) *awsddb.Client {
	t.Helper()
	endpoint := localEndpoint()
	client := awsddb.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: localCredentials{},
	}, func(o *awsddb.Options) { o.BaseEndpoint = aws.String(endpoint) })

	probeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, probeErr = client.ListTables(ctx, &awsddb.ListTablesInput{Limit: aws.Int32(1)})
	})
	if probeErr != nil {
		t.Skipf("dynamodb local is not reachable at %s (%v); "+
			"start it with: docker run -d --name ddblocal -p 8000:8000 amazon/dynamodb-local", endpoint, probeErr)
	}
	return client
}

// newInnerStore creates a table dedicated to the calling test, so tests cannot
// see each other's items and can run in parallel.
func newInnerStore(t *testing.T) *ddbstore.Store {
	t.Helper()
	client := testClient(t)
	table := "migtest_" + sanitiseTableName(t.Name()) + "_" + randomHex(4)
	if len(table) > 250 {
		table = table[:250]
	}

	if err := ddbstore.CreateTable(context.Background(), client, table); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		if _, err := client.DeleteTable(context.Background(), &awsddb.DeleteTableInput{TableName: aws.String(table)}); err != nil {
			t.Logf("delete table %s: %v", table, err)
		}
	})

	store, err := ddbstore.New(client, ddbstore.Options{TableName: table, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("ddbstore.New: %v", err)
	}
	return store
}

// sanitiseTableName keeps only what DynamoDB accepts in a table name. A
// subtest name is arbitrary prose — these tests name their cases after the
// sentence the code under test produces — so replacing a fixed list of
// characters is not enough; anything outside the accepted set becomes '_'.
func sanitiseTableName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// newStoreOnAMissingTable is a store whose table was never created, so every
// read fails with something that is not a miss.
func newStoreOnAMissingTable(t *testing.T) *ddbstore.Store {
	t.Helper()
	store, err := ddbstore.New(testClient(t), ddbstore.Options{
		TableName: "migtest_absent_" + randomHex(6),
		Logger:    discardLogger(),
	})
	if err != nil {
		t.Fatalf("ddbstore.New: %v", err)
	}
	return store
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s+%s@example.test", prefix, randomHex(6))
}

const (
	testPool      = "eu-west-1_EXAMPLE00"
	testOtherPool = "eu-west-1_EXAMPLE99"
	testSource    = "cognito"
)

func testRef() SourceRef { return SourceRef{Source: testSource, Pool: testPool} }

// fakeDirectory is the CognitoDirectory every test here drives. It is SDK-free,
// which is the point of the two-seam split in internal/integration/aws: nothing
// in this package, tests included, has to know what an AdminInitiateAuthInput
// looks like.
type fakeDirectory struct {
	mu sync.Mutex

	// users is the pool's contents, keyed by the username a caller asks for.
	users map[string]awsintegration.CognitoUser

	// passwords is what the pool accepts, keyed the same way.
	passwords map[string]string

	// getErr and verifyErr, when set, are returned instead of any answer.
	getErr    error
	verifyErr error

	getCalls    int
	verifyCalls int
	lastVerify  string
}

func newFakeDirectory() *fakeDirectory {
	return &fakeDirectory{
		users:     map[string]awsintegration.CognitoUser{},
		passwords: map[string]string{},
	}
}

func (f *fakeDirectory) add(username string, attrs map[string]string, password string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[username] = awsintegration.CognitoUser{
		Username:   username,
		Enabled:    true,
		Status:     "CONFIRMED",
		Attributes: attrs,
		CreatedAt:  time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC),
		UpdatedAt:  time.Date(2022, 3, 4, 5, 6, 7, 0, time.UTC),
	}
	if password != "" {
		f.passwords[username] = password
	}
}

func (f *fakeDirectory) counts() (get, verify int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getCalls, f.verifyCalls
}

func (f *fakeDirectory) ListUsers(_ context.Context, pageToken string, _ int32) (awsintegration.CognitoUserPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if pageToken != "" {
		return awsintegration.CognitoUserPage{}, nil
	}
	page := awsintegration.CognitoUserPage{}
	for _, u := range f.users {
		page.Users = append(page.Users, u)
	}
	return page, nil
}

func (f *fakeDirectory) GetUser(_ context.Context, username string) (awsintegration.CognitoUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	if f.getErr != nil {
		return awsintegration.CognitoUser{}, f.getErr
	}
	u, ok := f.users[username]
	if !ok {
		return awsintegration.CognitoUser{}, awsintegration.ErrCognitoUserNotFound
	}
	return u, nil
}

func (f *fakeDirectory) VerifyPassword(_ context.Context, username, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifyCalls++
	f.lastVerify = username
	if f.verifyErr != nil {
		return f.verifyErr
	}
	want, ok := f.passwords[username]
	if !ok {
		return awsintegration.ErrCognitoUserNotFound
	}
	if want != password {
		return awsintegration.ErrCognitoPasswordRejected
	}
	return nil
}

var _ awsintegration.CognitoDirectory = (*fakeDirectory)(nil)

// newMigrating builds the wrapper over a real store and the fake directory.
func newMigrating(t *testing.T, dir awsintegration.CognitoDirectory, mutate ...func(*Options)) *MigratingUserStore {
	t.Helper()
	opts := Options{
		Directory:  dir,
		Source:     testSource,
		UserPoolID: testPool,
		Logger:     discardLogger(),
	}
	for _, m := range mutate {
		m(&opts)
	}
	// After the mutators, so a test that supplies its own inner store does not
	// also pay for a table it will not use.
	if opts.Inner == nil {
		opts.Inner = newInnerStore(t)
	}
	store, err := New(opts)
	if err != nil {
		t.Fatalf("migrating.New: %v", err)
	}
	return store
}

// markerRecorded reports whether a marker for this deployment's pool was filed
// for userID by the read (or the create) that just happened on ctx.
//
// It exists because there is no other way to ask: the marker is deliberately not
// a field on auth.User, so a test cannot look at the value the store returned —
// which is exactly the property the design buys, and the reason every assertion
// about a marker in this package goes through the carrier.
func markerRecorded(t *testing.T, m *MigratingUserStore, userID string) bool {
	t.Helper()
	ctx := ddbstore.WithMigrationScope(context.Background())
	if _, err := m.GetUserByID(ctx, userID, ""); err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	marker, ok := ddbstore.TakeMigrationMarker(ctx, userID)
	if !ok {
		return false
	}
	return m.ref().Matches(marker)
}

func errorIsAny(err error, targets ...error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
