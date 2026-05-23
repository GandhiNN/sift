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

func stepFunctionsRisk(loggingEnabled, tracingEnabled bool) string {
	switch {
	case !loggingEnabled && !tracingEnabled:
		return "MEDIUM"
	case !loggingEnabled:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

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

	results := make([]audit.Finding, len(machines))
	bar := progress.NewBar(ctx, int64(len(machines)), "Auditing Step Functions security")
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for i, sm := range machines {
		wg.Add(1)
		go func(i int, sm sfntypes.StateMachineListItem) {
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
				results[i] = audit.ErrorFinding("stepfunctions", name, "describe", err)
				return
			}

			loggingEnabled := desc.LoggingConfiguration != nil &&
				desc.LoggingConfiguration.Level != sfntypes.LogLevelOff
			tracingEnabled := desc.TracingConfiguration != nil &&
				desc.TracingConfiguration.Enabled

			risk := stepFunctionsRisk(loggingEnabled, tracingEnabled)
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

			results[i] = audit.Finding{
				Service:     "stepfunctions",
				ResourceID:  name,
				Check:       "stepfunctions_security",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
		}(i, sm)
	}
	wg.Wait()

	out := results[:0]
	for _, f := range results {
		if f.ResourceID != "" {
			out = append(out, f)
		}
	}
	return out, nil
}
