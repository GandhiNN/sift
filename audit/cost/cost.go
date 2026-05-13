package cost

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
)

var PrevGenPrefixes = []string{
	"m1.",
	"m2.",
	"m3.",
	"m4.",
	"c1.",
	"c3.",
	"c4.",
	"r3.",
	"r4.",
	"i2.",
	"t1.",
	"t2.",
}

func Audit(ctx context.Context, cfg aws.Config, services []string) ([]audit.Finding, error) {

	allChecks := []struct {
		name string
		fn   func(context.Context, aws.Config) ([]audit.Finding, error)
	}{
		{"ec2", AuditEC2Cost},
		{"ebs", AuditEBSCost},
		{"rds", AuditRDSCost},
		{"s3", AuditS3Cost},
		{"eks", AuditEKSCost},
		{"network", AuditNetworkCost},
		{"cloudwatch", AuditCloudwatchCost},
		{"ecr", AuditECRCost},
		{"secrets", AuditSecretsCost},
		{"glue", AuditGlueCost},
		{"lambda", AuditLambdaCost},
		{"dynamodb", AuditDynamoDBCost},
		{"dms", AuditDMSCost},
		{"elb", AuditELBCost},
	}

	var checks []struct {
		name string
		fn   func(context.Context, aws.Config) ([]audit.Finding, error)
	}
	if len(services) == 0 {
		checks = allChecks
	} else {
		svcSet := make(map[string]bool)
		for _, s := range services {
			svcSet[s] = true
		}
		for _, c := range allChecks {
			if svcSet[c.name] {
				checks = append(checks, c)
			}
		}
	}

	results := make([][]audit.Finding, len(checks))

	if len(checks) == 1 {
		// Single service - run directly, let service show its own progress
		subCtx := progress.WithSubProgress(ctx, true)
		findings, err := checks[0].fn(subCtx, cfg)
		if err != nil {
			slog.Warn("cost check failed", "service", checks[0].name, "error", err)
			results[0] = []audit.Finding{{
				Service:   checks[0].name,
				Check:     "service_error",
				Status:    "ERROR",
				Detail:    fmt.Sprintf("audit failed: %v", err),
				RiskLevel: "UNKNOWN",
			}}
		} else {
			results[0] = findings
		}
	} else {
		// Multiple services - show orchestrator bar, supress sub-service bars
		subCtx := progress.WithSubProgress(ctx, false)
		bar := progress.NewOrchestratorBar(ctx, int64(len(checks)), "Auditing cost waste")
		var wg sync.WaitGroup
		for i, c := range checks {
			wg.Add(1)
			go func(i int, name string, fn func(context.Context, aws.Config) ([]audit.Finding, error)) {
				defer wg.Done()
				findings, err := fn(subCtx, cfg)
				if err != nil {
					slog.Warn("cost check failed", "service", name, "error", err)
					results[i] = []audit.Finding{{
						Service:   name,
						Check:     "service_error",
						Status:    "ERROR",
						Detail:    fmt.Sprintf("audit failed: %v", err),
						RiskLevel: "UNKNOWN",
					}}
				} else {
					results[i] = findings
				}
				bar.Done(name)
			}(i, c.name, c.fn)
		}
		wg.Wait()
	}

	var all []audit.Finding
	for _, findings := range results {
		all = append(all, findings...)
	}
	return all, nil
}
