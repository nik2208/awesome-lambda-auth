package dynamodb

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// TableAPI is the control-plane slice used to create a table. It is separate from
// API because the Lambda's IAM role should not hold CreateTable: production
// tables come from infrastructure code, and this helper exists for DynamoDB
// Local and for a developer's throwaway table.
type TableAPI interface {
	CreateTable(ctx context.Context, in *awsddb.CreateTableInput, optFns ...func(*awsddb.Options)) (*awsddb.CreateTableOutput, error)
	UpdateTimeToLive(ctx context.Context, in *awsddb.UpdateTimeToLiveInput, optFns ...func(*awsddb.Options)) (*awsddb.UpdateTimeToLiveOutput, error)
}

// gsi1Projection is INCLUDE of exactly three attributes.
//
// Not ALL: GSI1 indexes sessions, the highest-churn entity in the table, and a
// full projection would duplicate every session item — doubling storage and the
// write cost of every login and rotation — to save one round trip on an
// interactive admin read. Not KEYS_ONLY: ListForUser must return a linked
// account's id and creation time, and neither is in the key.
//
// Nothing secret is here by construction. A GSI is a second physical copy with
// its own export, its own PITR restore and its own blast radius, so passwordHash,
// totpSecret, refreshHash and every *Hash attribute exist in exactly one place.
var gsi1Projection = []string{attrType, "linkId", attrCreatedAt}

// CreateTable creates the single table and its one sparse GSI, matching
// docs/spec/data-model.md §2. It is idempotent: an existing table is left alone.
//
// PAY_PER_REQUEST because auth traffic is spiky and per-tenant unpredictable. A
// production deployment should add the on-demand ceiling, PITR, a customer-managed
// KMS key, deletion protection and streams (§6.1) — none of which DynamoDB Local
// honours, and all of which belong in infrastructure code rather than here.
func CreateTable(ctx context.Context, api TableAPI, tableName string) error {
	_, err := api.CreateTable(ctx, &awsddb.CreateTableInput{
		TableName:   aws.String(tableName),
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String(attrPK), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String(attrSK), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String(attrGSI1PK), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String(attrGSI1SK), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String(attrPK), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String(attrSK), KeyType: types.KeyTypeRange},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{{
			IndexName: aws.String(DefaultIndexName),
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String(attrGSI1PK), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String(attrGSI1SK), KeyType: types.KeyTypeRange},
			},
			Projection: &types.Projection{
				ProjectionType:   types.ProjectionTypeInclude,
				NonKeyAttributes: gsi1Projection,
			},
		}},
	})
	if err != nil {
		var inUse *types.ResourceInUseException
		if errors.As(err, &inUse) {
			return nil
		}
		return fmt.Errorf("dynamodb: create table %s: %w", tableName, err)
	}

	_, err = api.UpdateTimeToLive(ctx, &awsddb.UpdateTimeToLiveInput{
		TableName: aws.String(tableName),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			AttributeName: aws.String(attrTTL),
			Enabled:       aws.Bool(true),
		},
	})
	if err != nil {
		return fmt.Errorf("dynamodb: enable ttl on %s: %w", tableName, err)
	}
	return nil
}
