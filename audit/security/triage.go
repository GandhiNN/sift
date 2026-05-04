package security

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

func Triage(
	ctx context.Context,
	cfg aws.Config,
	logGroup string,
	targets []TriageTarget,
) ([]audit.Finding, error) {
	cwClient := cloudwatchlogs.NewFromConfig(cfg)
	roleCache := NewRoleCache()

	type triageResult struct {
		target      TriageTarget
		iamRisk     string
		iamDetails  []string
		publicConns []FlowEvent
	}

	results := make([]triageResult, len(targets))
	bar := progress.NewBar(ctx, int64(len(targets)), "Triaging instances")
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // limit to 5 concurrent

	for i, t := range targets {
		wg.Add(1)
		go func(i int, t TriageTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := triageResult{target: t}

			// IAM analysis
			if t.RoleARN != nil {
				finding, err := CachedAnalyzeRole(ctx, cfg, *t.RoleARN, roleCache)
				if err != nil {
					slog.Warn("IAM check failed", "instance", t.ResourceID, "error", err)
				} else {
					r.iamRisk = finding.RiskLevel
					for _, f := range finding.Findings {
						r.iamDetails = append(r.iamDetails, fmt.Sprintf("%s:%s(%s)", f.PolicyType, f.PolicyName, f.Issue))
					}
				}
			}

			// Flow log analysis
			if t.PrivateIP != nil {
				conns, err := FindPublicConnections(ctx, cwClient, logGroup, *t.PrivateIP)
				if err != nil {
					slog.Warn("flow log query failed", "resource", t.ResourceID, "error", err)
				} else {
					r.publicConns = conns
				}
			}
			results[i] = r
			bar.Add(1)
		}(i, t)
	}
	wg.Wait()

	var findings []audit.Finding
	for _, r := range results {
		connCount := len(r.publicConns)
		risk := triageRisk(r.target.OpenToWorld, r.target.IMDSv1, r.iamRisk, connCount)

		detail := fmt.Sprintf(
			"service=%s, open_to_world=%t, imdsv1=%t, public_connection=%d",
			r.target.Service,
			r.target.OpenToWorld,
			r.target.IMDSv1,
			connCount,
		)
		if r.iamRisk != "" {
			detail += fmt.Sprintf(", iam_risk=%s", r.iamRisk)
		}
		if len(r.iamDetails) > 0 {
			detail += fmt.Sprintf(", iam_findings=%s", strings.Join(r.iamDetails, ";"))
		}

		findings = append(findings, audit.Finding{
			Service:    r.target.Service,
			ResourceID: r.target.ResourceID,
			Check:      "triage",
			Status:     statusFromRisk(risk),
			Detail:     detail,
			RiskLevel:  risk,
		})
	}
	return findings, nil
}

func triageRisk(openToWorld, imdsV1 bool, iamRisk string, connCount int) string {
	if connCount > 0 && openToWorld {
		return "CRITICAL"
	}
	if connCount > 0 {
		return "HIGH"
	}
	if iamRisk == "HIGH" && openToWorld {
		return "HIGH"
	}
	if openToWorld || imdsV1 {
		return "MEDIUM"
	}
	return "LOW"
}
