package security

import (
	"context"
	"fmt"
	"sync"

	"sift/audit"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type dynamoDBTable struct {
	name               string
	encrypted          bool
	pitr               bool
	deletionProtection bool
	tags               map[string]string
}

func dynamoDBRisk(encrypted, pitr, deletionProtection bool) string {
	switch {
	case !encrypted:
		return "HIGH"
	case !pitr && !deletionProtection:
		return "MEDIUM"
	case pitr && deletionProtection:
		return "MINIMAL"
	default:
		return "LOW"
	}
}

func parseDynamoDBTable(
	ctx context.Context,
	client *dynamodb.Client,
	name string,
) (*dynamoDBTable, error) {
	desc, err := client.DescribeTable(
		ctx,
		&dynamodb.DescribeTableInput{TableName: aws.String(name)},
	)
	if err != nil {
		return nil, err
	}
	table := desc.Table

	t := &dynamoDBTable{
		name:               name,
		encrypted:          true,
		deletionProtection: aws.ToBool(table.DeletionProtectionEnabled),
	}

	if table.SSEDescription != nil && table.SSEDescription.Status == dbtypes.SSEStatusDisabled {
		t.encrypted = false
	}

	cb, err := client.DescribeContinuousBackups(
		ctx,
		&dynamodb.DescribeContinuousBackupsInput{TableName: aws.String(name)},
	)
	if err == nil && cb.ContinuousBackupsDescription != nil &&
		cb.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
		t.pitr = cb.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == dbtypes.PointInTimeRecoveryStatusEnabled
	}

	tagResp, err := client.ListTagsOfResource(
		ctx,
		&dynamodb.ListTagsOfResourceInput{ResourceArn: table.TableArn},
	)
	if err == nil {
		t.tags = make(map[string]string, len(tagResp.Tags))
		for _, tag := range tagResp.Tags {
			t.tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
	}

	return t, nil
}

func AuditDynamoDB(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := dynamodb.NewFromConfig(cfg)

	var tableNames []string
	paginator := dynamodb.NewListTablesPaginator(client, &dynamodb.ListTablesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list tables: %w", err)
		}
		tableNames = append(tableNames, page.TableNames...)
	}

	results := make([]audit.Finding, len(tableNames))
	bar := progress.NewBar(ctx, int64(len(tableNames)), "Auditing DynamoDB tables")

	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for i, name := range tableNames {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			t, err := parseDynamoDBTable(ctx, client, name)
			if err != nil {
				results[i] = audit.ErrorFinding("dynamodb", name, "table_posture", err)
				bar.Add(1)
				return
			}

			risk := dynamoDBRisk(t.encrypted, t.pitr, t.deletionProtection)
			detail := fmt.Sprintf(
				"encrypted=%t, pitr=%t, deletion_protection=%t",
				t.encrypted, t.pitr, t.deletionProtection,
			)

			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend(
					"security",
					"dynamodb",
					"dynamodb_security",
					t.name,
					detail,
				)
			}

			results[i] = audit.Finding{
				Service:     "dynamodb",
				ResourceID:  t.name,
				Tags:        t.tags,
				Check:       "table_posture",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
			bar.Add(1)
		}(i, name)
	}
	wg.Wait()

	var findings []audit.Finding
	for _, f := range results {
		if f.ResourceID != "" {
			findings = append(findings, f)
		}
	}
	return findings, nil
}
