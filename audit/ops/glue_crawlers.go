package ops

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
)

func auditCrawlerCount(
	ctx context.Context,
	client *glue.Client,
	_ aws.Config,
) ([]audit.Finding, error) {
	spinner := progress.NewSpinner(ctx, "Counting Glue crawlers")

	var count int
	input := &glue.GetCrawlersInput{}
	for {
		resp, err := client.GetCrawlers(ctx, input)
		if err != nil {
			spinner.Finish()
			return nil, fmt.Errorf("get crawlers: %w", err)
		}
		count += len(resp.Crawlers)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	spinner.Finish()

	return []audit.Finding{{
		Service:    "glue",
		ResourceID: "crawlers",
		Check:      "crawler_count",
		Status:     "INFO",
		Detail:     fmt.Sprintf("total_crawlers=%d", count),
		RiskLevel:  "MINIMAL",
	}}, nil
}
