package security

import (
	"context"
	"fmt"
	"sync"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

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

			results[i] = auditDynamoDBTable(ctx, client, name)
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

func auditDynamoDBTable(ctx context.Context, client *dynamodb.Client, name string) audit.Finding {
	desc, err := client.DescribeTable(
		ctx,
		&dynamodb.DescribeTableInput{TableName: aws.String(name)},
	)
	if err != nil {
		return audit.Finding{
			Service:    "dynamodb",
			ResourceID: name,
			Check:      "table_posture",
			Status:     "ERROR",
			Detail:     fmt.Sprintf("failed to describe table: %v", err),
			RiskLevel:  "UNKNOWN",
		}
	}
	table := desc.Table

	encrypted := true
	if table.SSEDescription != nil && table.SSEDescription.Status == dbtypes.SSEStatusDisabled {
		encrypted = false
	}

	pitr := false
	cb, err := client.DescribeContinuousBackups(
		ctx,
		&dynamodb.DescribeContinuousBackupsInput{TableName: aws.String(name)},
	)
	if err == nil && cb.ContinuousBackupsDescription != nil &&
		cb.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
		pitr = cb.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == dbtypes.PointInTimeRecoveryStatusEnabled
	}

	deletionProtection := aws.ToBool(table.DeletionProtectionEnabled)

	risk, detail := dynamoDBRisk(encrypted, pitr, deletionProtection)
	return audit.Finding{
		Service:    "dynamodb",
		ResourceID: name,
		Check:      "table_posture",
		Status:     statusFromRisk(risk),
		Detail:     detail,
		RiskLevel:  risk,
	}
}

func dynamoDBRisk(encrypted, pitr, deletionProtection bool) (string, string) {
	if !encrypted {
		return "HIGH", "encryption not enabled"
	}
	if !pitr && !deletionProtection {
		return "MEDIUM", "no PITR, no deletion protection"
	}
	if pitr && deletionProtection {
		return "MINIMAL", "encrypted, PITR enabled, deletion protection on"
	}
	detail := "encrypted"
	if !pitr {
		detail += ", no PITR"
	}
	if !deletionProtection {
		detail += ", no deletion protection"
	}
	return "LOW", detail
}
