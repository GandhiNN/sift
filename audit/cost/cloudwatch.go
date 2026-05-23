package cost

import (
	"context"
	"fmt"
	"sync"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type logGroupEntry struct {
	name          string
	sizeGB        float64
	retentionSet  bool
	retentionDays int32
	tags          map[string]string
}

func parseLogGroup(
	ctx context.Context,
	client *cloudwatchlogs.Client,
	lg cwltypes.LogGroup,
) logGroupEntry {
	e := logGroupEntry{
		name:          aws.ToString(lg.LogGroupName),
		sizeGB:        float64(aws.ToInt64(lg.StoredBytes)) / (1024 * 1024 * 1024),
		retentionSet:  lg.RetentionInDays != nil,
		retentionDays: aws.ToInt32(lg.RetentionInDays),
	}
	tagResp, err := client.ListTagsForResource(ctx, &cloudwatchlogs.ListTagsForResourceInput{
		ResourceArn: lg.LogGroupArn,
	})
	if err == nil {
		e.tags = tagResp.Tags
	}
	return e
}

func AuditCloudwatchCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := cloudwatchlogs.NewFromConfig(cfg)

	var allGroups []cwltypes.LogGroup
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(
		client,
		&cloudwatchlogs.DescribeLogGroupsInput{},
	)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe log groups: %w", err)
		}
		allGroups = append(allGroups, page.LogGroups...)
	}

	results := make([]audit.Finding, len(allGroups))
	bar := progress.NewBar(ctx, int64(len(allGroups)), "Auditing CloudWatch Logs cost")
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for i, lg := range allGroups {
		wg.Add(1)
		go func(i int, lg cwltypes.LogGroup) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer bar.Add(1)

			e := parseLogGroup(ctx, client, lg)

			if !e.retentionSet {
				results[i] = audit.Finding{
					Service:    "cloudwatch_logs",
					ResourceID: e.name,
					Tags:       e.tags,
					Check:      "no_retention_policy",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"stored=%.2fGB, logs never expire ($0.03/GB/mo)",
						e.sizeGB,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: pricing.CloudWatchLogsMonthly(e.sizeGB),
					Remediation: remediation.Recommend(
						"cost",
						"cloudwatch_logs",
						"no_retention_policy",
						e.name,
						"logs never expire",
					),
				}
			} else {
				results[i] = audit.Finding{
					Service:              "cloudwatch_logs",
					ResourceID:           e.name,
					Tags:                 e.tags,
					Check:                "no_retention_policy",
					Status:               "PASS",
					Detail:               fmt.Sprintf("retention=%d days", e.retentionDays),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: pricing.CloudWatchLogsMonthly(e.sizeGB),
				}
			}
		}(i, lg)
	}
	wg.Wait()

	return results, nil
}
