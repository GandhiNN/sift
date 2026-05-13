package cost

import (
	"context"
	"fmt"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type logGroupEntry struct {
	name   string
	sizeGB float64
	tags   map[string]string
}

func parseLogGroup(
	ctx context.Context,
	client *cloudwatchlogs.Client,
	lg cwltypes.LogGroup,
) logGroupEntry {
	e := logGroupEntry{
		name:   aws.ToString(lg.LogGroupName),
		sizeGB: float64(aws.ToInt64(lg.StoredBytes)) / (1024 * 1024 * 1024),
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
			e := parseLogGroup(ctx, client, lg)
			if lg.RetentionInDays == nil {
				findings = append(findings, audit.Finding{
					Service:    "cloudwatch_logs",
					ResourceID: e.name,
					Tags:       e.tags,
					Check:      "no_retention_policy",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"stored=%.2fGB, logs never expire ($0.03/GB/mo)",
						e.sizeGB,
					),
					RiskLevel: "MEDIUM",
				})
			} else {
				findings = append(findings, audit.Finding{
					Service:    "cloudwatch_logs",
					ResourceID: e.name,
					Tags:       e.tags,
					Check:      "no_retention_policy",
					Status:     "PASS",
					Detail:     fmt.Sprintf("retention=%d days", aws.ToInt32(lg.RetentionInDays)),
					RiskLevel:  "MINIMAL",
				})
			}
		}
	}
	return findings, nil
}
