package security

import (
	"context"
	"log/slog"
	"sync"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type TriageTarget struct {
	ResourceID  string
	Service     string
	PrivateIP   *string
	RoleARN     *string
	OpenToWorld bool
	IMDSv1      bool
}

func statusFromRisk(risk string) string {
	if risk == "MINIMAL" {
		return "PASS"
	}
	return "FAIL"
}

func Audit(ctx context.Context, cfg aws.Config, services []string) ([]audit.Finding, error) {
	allChecks := []struct {
		name string
		fn   func(context.Context, aws.Config) ([]audit.Finding, error)
	}{
		{"ec2", AuditEC2},
		{"sagemaker", AuditSagemaker},
		{"s3", AuditS3},
		{"rds", AuditRDS},
		{"eks", AuditEKS},
		{"iam", AuditIAMHygiene},
		{"secrets", AuditSecrets},
		{"glue", AuditGlue},
		{"baseline", AuditBaseline},
		{"lambda", AuditLambda},
		{"dynamodb", AuditDynamoDB},
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
		subCtx := progress.WithSubProgress(ctx, true)
		findings, err := checks[0].fn(subCtx, cfg)
		if err != nil {
			slog.Warn("security check failed", "service", checks[0].name, "error", err)
		} else {
			results[0] = findings
		}
	} else {
		subCtx := progress.WithSubProgress(ctx, false)
		bar := progress.NewOrchestratorBar(ctx, int64(len(checks)), "Running security audit")
		var wg sync.WaitGroup
		for i, c := range checks {
			wg.Add(1)
			go func(i int, name string, fn func(context.Context, aws.Config) ([]audit.Finding, error)) {
				defer wg.Done()
				findings, err := fn(subCtx, cfg)
				if err != nil {
					slog.Warn("security check failed", "service", name, "error", err)
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
