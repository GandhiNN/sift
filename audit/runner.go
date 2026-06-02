package audit

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type CheckFn func(context.Context, aws.Config) ([]Finding, error)

type Checker struct {
	Name string
	Fn   CheckFn
}

func RunChecks(
	ctx context.Context,
	cfg aws.Config,
	services []string,
	all []Checker,
	label string,
) ([]Finding, error) {
	checks := all
	if len(services) > 0 {
		svcSet := make(map[string]bool, len(services))
		for _, s := range services {
			svcSet[s] = true
		}
		checks = nil
		for _, c := range all {
			if svcSet[c.Name] {
				checks = append(checks, c)
			}
		}
	}

	if len(checks) == 0 {
		return nil, nil
	}

	results := make([][]Finding, len(checks))

	if len(checks) == 1 {
		subCtx := progress.WithSubProgress(ctx, true)
		findings, err := checks[0].Fn(subCtx, cfg)
		if err != nil {
			if isServiceNotAvailable(err) {
				slog.Debug("service not available", "service", checks[0].Name, "error", err)
				results[0] = []Finding{{
					Service:   checks[0].Name,
					Check:     "service_availability",
					Status:    "PASS",
					Detail:    "service not active or not subscribed in this account",
					RiskLevel: "MINIMAL",
				}}
			} else {
				slog.Warn("check failed", "service", checks[0].Name, "error", err)
				results[0] = []Finding{ErrorFinding(checks[0].Name, "", "service_error", err)}
			}
		} else {
			results[0] = findings
		}
	} else {
		subCtx := progress.WithSubProgress(ctx, false)
		bar := progress.NewOrchestratorBar(ctx, int64(len(checks)), label)
		var wg sync.WaitGroup
		for i, c := range checks {
			wg.Add(1)
			go func(i int, name string, fn CheckFn) {
				defer wg.Done()
				findings, err := fn(subCtx, cfg)
				if err != nil {
					if isServiceNotAvailable(err) {
						slog.Debug("service not available", "service", name, "error", err)
						results[i] = []Finding{{
							Service:   name,
							Check:     "service_availability",
							Status:    "PASS",
							Detail:    "service not active or not subscribed in this account",
							RiskLevel: "MINIMAL",
						}}
					} else {
						slog.Warn("check failed", "service", name, "error", err)
						results[i] = []Finding{{
							Service:   name,
							Check:     "service_error",
							Status:    "ERROR",
							Detail:    fmt.Sprintf("audit failed: %v", err),
							RiskLevel: "UNKNOWN",
						}}
					}
				} else {
					results[i] = findings
				}
				bar.Done(name)
			}(i, c.Name, c.Fn)
		}
		wg.Wait()
	}

	var out []Finding
	for _, f := range results {
		out = append(out, f...)
	}
	return out, nil
}

func isServiceNotAvailable(err error) bool {
	msg := err.Error()
	indicators := []string{
		"ResourceNotFoundException",
		"SubscriptionRequiredException",
		"OptInRequired",
		"InvalidClientTokenId",
		"UnrecognizedClientException",
		"NotSignedUp",
		"is not subscribed",
		"is not authorized to use this service",
		"Namespace default not found",
	}
	for _, ind := range indicators {
		if strings.Contains(msg, ind) {
			return true
		}
	}
	return false
}
