package ops

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
)

func auditJobVersions(
	ctx context.Context,
	client *glue.Client,
	_ aws.Config,
) ([]audit.Finding, error) {
	spinner := progress.NewSpinner(ctx, "Checking Glue job versions")

	versionCounts := make(map[string]int)
	input := &glue.GetJobsInput{}
	for {
		resp, err := client.GetJobs(ctx, input)
		if err != nil {
			spinner.Finish()
			return nil, fmt.Errorf("get jobs: %w", err)
		}
		for _, job := range resp.Jobs {
			version := aws.ToString(job.GlueVersion)
			if version == "" {
				version = "unknown"
			}
			versionCounts[version]++
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	spinner.Finish()

	var findings []audit.Finding
	for version, count := range versionCounts {
		risk := "MINIMAL"
		if version == "0.9" || version == "1.0" || version == "2.0" {
			risk = "MEDIUM"
		}
		findings = append(findings, audit.Finding{
			Service:    "glue",
			ResourceID: fmt.Sprintf("jobs/version-%s", version),
			Check:      "job_version_distribution",
			Status:     "INFO",
			Detail:     fmt.Sprintf("glue_version=%s, count=%d", version, count),
			RiskLevel:  risk,
		})
	}
	return findings, nil
}
