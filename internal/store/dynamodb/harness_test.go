package dynamodb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// These tests run against DynamoDB Local, because the whole point of the store is
// the behaviour of conditional writes and transactions under concurrency, and a
// hand-written fake would only encode the author's belief about what DynamoDB
// does. They skip cleanly when no endpoint is reachable, so a plain checkout
// still has a green suite.
//
//	docker run -d --name ddblocal -p 8000:8000 amazon/dynamodb-local
//	go test -race -count=1 ./internal/store/dynamodb/...
const defaultLocalEndpoint = "http://localhost:8000"

func localEndpoint() string {
	if ep := os.Getenv("DYNAMODB_ENDPOINT"); ep != "" {
		return ep
	}
	return defaultLocalEndpoint
}

// localCredentials avoids a dependency on the SDK's credentials module for what
// DynamoDB Local ignores anyway: it validates the signature's shape, not its
// contents.
type localCredentials struct{}

func (localCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     "local",
		SecretAccessKey: "local",
		Source:          "dynamodb-local-test",
	}, nil
}

// The reachability probe is done once per process, not once per test: with no
// endpoint the SDK spends seconds retrying a refused connection, and paying that
// for every test would make a plain checkout unpleasantly slow.
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
	}, func(o *awsddb.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})

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

// newStore creates a table dedicated to the calling test, so tests cannot see
// each other's items and can run in parallel.
func newStore(t *testing.T, mutate ...func(*Options)) (*Store, *awsddb.Client) {
	t.Helper()
	client := testClient(t)
	table := testTableName(t)

	ctx := context.Background()
	if err := CreateTable(ctx, client, table); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		if _, err := client.DeleteTable(context.Background(), &awsddb.DeleteTableInput{
			TableName: aws.String(table),
		}); err != nil {
			t.Logf("delete table %s: %v", table, err)
		}
	})

	opts := Options{
		TableName: table,
		// Discard the degraded-rotation warning: several tests exercise that path
		// on purpose and the noise would drown the failures that matter.
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, m := range mutate {
		m(&opts)
	}
	store, err := New(client, opts)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return store, client
}

func testTableName(t *testing.T) string {
	t.Helper()
	name := strings.NewReplacer("/", "_", " ", "_", "#", "_").Replace(t.Name())
	if len(name) > 200 {
		name = name[:200]
	}
	return "authtest_" + name + "_" + randomHex(4)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// hashOf mirrors the core's hashToken (security.go:40-43) so the values under
// test have the shape the store will really see.
func hashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// rawItem reads an item straight from the table, bypassing the codecs. Assertions
// about attributes the auth.Session struct cannot carry — revokedReason, gen —
// have nowhere else to look.
func rawItem(t *testing.T, client *awsddb.Client, table, pk, sk string) map[string]types.AttributeValue {
	t.Helper()
	out, err := client.GetItem(context.Background(), &awsddb.GetItemInput{
		TableName:      aws.String(table),
		Key:            key(pk, sk),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("raw get %s/%s: %v", pk, sk, err)
	}
	return out.Item
}

func mustNotExist(t *testing.T, client *awsddb.Client, table, pk, sk string) {
	t.Helper()
	if m := rawItem(t, client, table, pk, sk); len(m) != 0 {
		t.Fatalf("expected %s/%s to be absent, got %v", pk, sk, m)
	}
}

func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s+%s@example.test", prefix, randomHex(6))
}

func uniqueID(prefix string) string {
	return prefix + "_" + randomHex(16)
}
