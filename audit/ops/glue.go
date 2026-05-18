package ops

import (
	"context"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
)

var glueChecks = map[string]func(context.Context, *glue.Client, aws.Config) ([]audit.Finding, error){
	"table_versions": auditTableVersions,
	"crawlers":       auditCrawlerCount,
	"job_versions":   auditJobVersions,
}

func AuditGlueOps(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := glue.NewFromConfig(cfg)
	var findings []audit.Finding

	checks := glueChecks
	if filterChecks := audit.GetChecks(ctx); len(filterChecks) > 0 {
		checks = make(
			map[string]func(context.Context, *glue.Client, aws.Config) ([]audit.Finding, error),
		)
		for _, name := range filterChecks {
			if fn, ok := glueChecks[name]; ok {
				checks[name] = fn
			}
		}
	}
	for _, fn := range checks {
		results, err := fn(ctx, client, cfg)
		if err != nil {
			return nil, err
		}
		findings = append(findings, results...)
	}

	return findings, nil
}
