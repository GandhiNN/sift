package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

func init() {
	audit.Register(Module, audit.Checker{Name: "stepfunctions", Fn: AuditStepFunctions})
}

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

	results := audit.ProcessAll(
		ctx,
		machines,
		"Auditing Step Functions security",
		func(ctx context.Context, sm sfntypes.StateMachineListItem) audit.Finding {
			arn := aws.ToString(sm.StateMachineArn)
			name := aws.ToString(sm.Name)

			desc, err := client.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
				StateMachineArn: &arn,
			})
			if err != nil {
				return audit.ErrorFinding("stepfunctions", name, "describe", err)
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

			return audit.Finding{
				Service:     "stepfunctions",
				ResourceID:  name,
				Check:       "stepfunctions_security",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
		},
	)

	return results, nil
}
