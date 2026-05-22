package cost

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

func AuditStepFunctionsCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := sfn.NewFromConfig(cfg)

	var machines []sfntypes.StateMachineListItem
	input := &sfn.ListStateMachinesInput{}
	for {
		resp, err := client.ListStateMachines(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list state machines: %w", err)
		}
		machines = append(machines, resp.StateMachines...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	bar := progress.NewBar(ctx, int64(len(machines)), "Auditing Step Functions cost")
	var findings []audit.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	cutoff := time.Now().AddDate(0, 0, -30)

	for _, sm := range machines {
		wg.Add(1)
		go func(sm sfntypes.StateMachineListItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer bar.Add(1)

			arn := aws.ToString(sm.StateMachineArn)
			name := aws.ToString(sm.Name)

			// Check for recent executions
			execResp, err := client.ListExecutions(ctx, &sfn.ListExecutionsInput{
				StateMachineArn: &arn,
				MaxResults:      1,
			})
			if err != nil {
				mu.Lock()
				findings = append(
					findings,
					audit.ErrorFinding("stepfunctions", name, "list_executions", err),
				)
				mu.Unlock()
				return
			}

			if len(execResp.Executions) == 0 || execResp.Executions[0].StartDate.Before(cutoff) {
				detail := fmt.Sprintf("type=%s, no executions in last 30 days", sm.Type)
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:    "stepfunctions",
					ResourceID: name,
					Check:      "unused_state_machine",
					Status:     "WARN",
					Detail:     detail,
					RiskLevel:  "LOW",
					Remediation: remediation.Recommend(
						"cost",
						"stepfunctions",
						"unused_state_machine",
						name,
						detail,
					),
				})
				mu.Unlock()
			} else {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:    "stepfunctions",
					ResourceID: name,
					Check:      "unused_state_machine",
					Status:     "PASS",
					Detail:     fmt.Sprintf("type=%s, last_execution=%s", sm.Type, execResp.Executions[0].StartDate.Format("2006-01-02")),
					RiskLevel:  "MINIMAL",
				})
				mu.Unlock()
			}
		}(sm)
	}
	wg.Wait()

	return findings, nil
}
