// Package aws holds the AWS-specific integrations the rest of the product
// injects rather than imports.
//
// The auth core and the configuration loader stay cloud-agnostic on purpose, so
// the AWS SDK is confined to this package and to internal/store/dynamodb. A
// constructor lives here rather than in cmd/auth because the entrypoint is the
// one place that must be able to compose a deployment without knowing which
// cloud it runs on: it asks for a store, not for a session, a credential chain
// and an endpoint resolver.
package aws

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// DynamoDBOptions configures the client. Both fields are optional: an empty
// Region falls back to the AWS_REGION the Lambda runtime always sets, and an
// empty Endpoint uses the real service.
type DynamoDBOptions struct {
	// Region overrides the region the default credential/config chain resolves.
	Region string

	// Endpoint points the client at something other than the real service —
	// DynamoDB Local in a container, or a VPC endpoint. It is an operator knob
	// (stores.connection.endpoint), not a test hook: unit tests inject a fake
	// dynamodb.API instead of talking to a socket.
	Endpoint string
}

// NewDynamoDBClient builds a DynamoDB client from the ambient AWS
// configuration.
//
// It performs no network I/O for the credential source a Lambda actually uses
// (the runtime's environment variables), which is what makes it safe to call
// once at cold start on the critical path. It is deliberately not called per
// request: LoadDefaultConfig walks the whole config/credential chain, and
// rebuilding the client per invocation also throws away the HTTP connection
// pool, turning every DynamoDB call into a fresh TLS handshake.
func NewDynamoDBClient(ctx context.Context, opts DynamoDBOptions) (*awsddb.Client, error) {
	var loadOpts []func(*awsconfig.LoadOptions) error
	if opts.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(opts.Region))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("aws: load default configuration: %w", err)
	}

	var clientOpts []func(*awsddb.Options)
	if endpoint := opts.Endpoint; endpoint != "" {
		clientOpts = append(clientOpts, func(o *awsddb.Options) { o.BaseEndpoint = &endpoint })
	}
	return awsddb.NewFromConfig(cfg, clientOpts...), nil
}
