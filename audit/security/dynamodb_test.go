package security

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type mockDynamoDBClient struct {
	table *dbtypes.TableDescription
	pitr  dbtypes.PointInTimeRecoveryStatus
}

func (m *mockDynamoDBClient) DescribeTable(
	_ context.Context,
	_ *dynamodb.DescribeTableInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.DescribeTableOutput, error) {
	return &dynamodb.DescribeTableOutput{Table: m.table}, nil
}

func (m *mockDynamoDBClient) DescribeContinuousBackups(
	_ context.Context,
	_ *dynamodb.DescribeContinuousBackupsInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.DescribeContinuousBackupsOutput, error) {
	return &dynamodb.DescribeContinuousBackupsOutput{
		ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
			PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
				PointInTimeRecoveryStatus: m.pitr,
			},
		},
	}, nil
}

func (m *mockDynamoDBClient) ListTagsOfResource(
	_ context.Context,
	_ *dynamodb.ListTagsOfResourceInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.ListTagsOfResourceOutput, error) {
	return &dynamodb.ListTagsOfResourceOutput{}, nil
}

func TestParseDynamoDBTable(t *testing.T) {
	tests := []struct {
		name       string
		sse        *dbtypes.SSEDescription
		pitr       dbtypes.PointInTimeRecoveryStatus
		delProtect bool
		wantRisk   string
	}{
		{
			name:       "fully configured",
			sse:        nil, // nil means default encryption (enabled)
			pitr:       dbtypes.PointInTimeRecoveryStatusEnabled,
			delProtect: true,
			wantRisk:   "MINIMAL",
		},
		{
			name:       "no encryption",
			sse:        &dbtypes.SSEDescription{Status: dbtypes.SSEStatusDisabled},
			pitr:       dbtypes.PointInTimeRecoveryStatusEnabled,
			delProtect: true,
			wantRisk:   "HIGH",
		},
		{
			name:       "no pitr no deletion protection",
			sse:        nil,
			pitr:       dbtypes.PointInTimeRecoveryStatusDisabled,
			delProtect: false,
			wantRisk:   "MEDIUM",
		},
		{
			name:       "pitr only",
			sse:        nil,
			pitr:       dbtypes.PointInTimeRecoveryStatusEnabled,
			delProtect: false,
			wantRisk:   "LOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDynamoDBClient{
				table: &dbtypes.TableDescription{
					TableName: aws.String("test-table"),
					TableArn: aws.String(
						"arn:aws:dynamodb:us-east-1:123:table/test-table",
					),
					SSEDescription:            tt.sse,
					DeletionProtectionEnabled: &tt.delProtect,
				},
				pitr: tt.pitr,
			}

			tbl, err := parseDynamoDBTable(context.Background(), mock, "test-table")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			risk := dynamoDBRisk(tbl.encrypted, tbl.pitr, tbl.deletionProtection)
			if risk != tt.wantRisk {
				t.Errorf("got risk %s, want %s", risk, tt.wantRisk)
			}
		})
	}
}
