package security

import (
	"context"
	"fmt"
	"sync"

	"sift/audit"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

func AuditStepFunctions(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
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

	bar := progress.NewBar(ctx, int64(len(machines)), "Auditing Step Functions security")
	var findings []audit.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for _, sm := range machines {
		wg.Add(1)
		go func(sm sfntypes.StateMachineListItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer bar.Add(1)

			arn := aws.ToString(sm.StateMachineArn)
			name := aws.ToString(sm.Name)

			desc, err := client.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
				StateMachineArn: &arn,
			})
			if err != nil {
				mu.Lock()
				findings = append(
					findings,
					audit.ErrorFinding("stepfunctions", name, "describe", err),
				)
				mu.Unlock()
				return
			}

			loggingEnabled := desc.LoggingConfiguration != nil &&
				desc.LoggingConfiguration.Level != sfntypes.LogLevelOff

			tracingEnabled := desc.TracingConfiguration != nil &&
				desc.TracingConfiguration.Enabled

			risk := "MINIMAL"
			if !loggingEnabled && !tracingEnabled {
				risk = "MEDIUM"
			} else if !loggingEnabled {
				risk = "LOW"
			}

			detail := fmt.Sprintf(
				"logging=%t, tracing=%t, type=%s",
				loggingEnabled,
				tracingEnabled,
				sm.Type,
			)

			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend(
					"security",
					"stepfunctions",
					"stepfunctions_security",
					name,
					detail,
				)
			}

			mu.Lock()
			findings = append(findings, audit.Finding{
				Service:     "stepfunctions",
				ResourceID:  name,
				Check:       "stepfunctions_security",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			})
			mu.Unlock()
		}(sm)
	}
	wg.Wait()

	return findings, nil
}
