package cost

import (
	"context"
	"fmt"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

func AuditCloudwatchCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := cloudwatchlogs.NewFromConfig(cfg)
	var findings []audit.Finding

	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(
		client,
		&cloudwatchlogs.DescribeLogGroupsInput{},
	)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe log groups: %w", err)
		}
		for _, lg := range page.LogGroups {
			if lg.RetentionInDays == nil {
				name := aws.ToString(lg.LogGroupName)
				sizeGB := float64(aws.ToInt64(lg.StoredBytes)) / (1024 * 1024 * 1024)
				findings = append(findings, audit.Finding{
					Service:    "cloudwatch_logs",
					ResourceID: name,
					Check:      "no_retention_policy",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"stored=%.2fGB, logs never expire ($0.03/GB/mo)",
						sizeGB,
					),
					RiskLevel: "MEDIUM",
				})
			}
		}
	}
	return findings, nil
}
