package cost

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

func AuditDynamoDBCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
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

	type result struct {
		findings []audit.Finding
	}
	results := make([]result, len(tableNames))
	bar := progress.NewBar(ctx, int64(len(tableNames)), "Auditing DynamoDB cost")

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for i, name := range tableNames {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[i] = result{findings: auditDynamoDBTableCost(ctx, client, name)}
			bar.Add(1)
		}(i, name)
	}
	wg.Wait()

	var findings []audit.Finding
	for _, r := range results {
		findings = append(findings, r.findings...)
	}
	return findings, nil
}

func auditDynamoDBTableCost(
	ctx context.Context,
	client *dynamodb.Client,
	name string,
) []audit.Finding {
	desc, err := client.DescribeTable(
		ctx,
		&dynamodb.DescribeTableInput{TableName: aws.String(name)},
	)
	if err != nil {
		return nil
	}
	table := desc.Table
	var findings []audit.Finding

	if table.BillingModeSummary == nil ||
		table.BillingModeSummary.BillingMode == dbtypes.BillingModeProvisioned {
		readCap := int64(0)
		writeCap := int64(0)
		if table.ProvisionedThroughput != nil {
			readCap = aws.ToInt64(table.ProvisionedThroughput.ReadCapacityUnits)
			writeCap = aws.ToInt64(table.ProvisionedThroughput.WriteCapacityUnits)
		}
		if readCap > 0 || writeCap > 0 {
			findings = append(findings, audit.Finding{
				Service:    "dynamodb",
				ResourceID: name,
				Check:      "provisioned_mode",
				Status:     "WARN",
				Detail: fmt.Sprintf(
					"provisioned mode (RCU=%d, WCU=%d) - consider on-demand if traffic is unpredictable",
					readCap,
					writeCap,
				),
				RiskLevel: "LOW",
			})
		}
	}

	for _, gsi := range table.GlobalSecondaryIndexes {
		if gsi.ItemCount != nil && aws.ToInt64(gsi.ItemCount) == 0 {
			findings = append(findings, audit.Finding{
				Service:    "dynamodb",
				ResourceID: fmt.Sprintf("%s/%s", name, aws.ToString(gsi.IndexName)),
				Check:      "unused_gsi",
				Status:     "WARN",
				Detail:     "GSI has zero items - wasting provisioned capacity",
				RiskLevel:  "MEDIUM",
			})
		}
	}
	return findings
}
