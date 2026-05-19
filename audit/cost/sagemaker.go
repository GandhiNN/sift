package cost

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/progress"
	"sift/audit/remediation"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	smtypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
)

type sagemakerCostEntry struct {
	name         string
	status       string
	instanceType string
}

func parseSagemakerCostEntry(
	desc *sagemaker.DescribeNotebookInstanceOutput,
	name string,
) sagemakerCostEntry {
	return sagemakerCostEntry{
		name:         name,
		status:       string(desc.NotebookInstanceStatus),
		instanceType: string(desc.InstanceType),
	}
}

func AuditSagemakerCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := sagemaker.NewFromConfig(cfg)

	var names []string
	input := &sagemaker.ListNotebookInstancesInput{}
	for {
		resp, err := client.ListNotebookInstances(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list notebook instances: %w", err)
		}
		for _, nb := range resp.NotebookInstances {
			if nb.NotebookInstanceName != nil {
				names = append(names, *nb.NotebookInstanceName)
			}
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	bar := progress.NewBar(ctx, int64(len(names)), "Auditing SageMaker cost")
	var findings []audit.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer bar.Add(1)

			desc, err := client.DescribeNotebookInstance(
				ctx,
				&sagemaker.DescribeNotebookInstanceInput{
					NotebookInstanceName: &name,
				},
			)
			if err != nil {
				mu.Lock()
				findings = append(findings, audit.ErrorFinding("sagemaker", name, "describe", err))
				mu.Unlock()
				return
			}

			e := parseSagemakerCostEntry(desc, name)
			monthlyCost := pricing.EC2Monthly(e.instanceType)

			var finding audit.Finding
			switch smtypes.NotebookInstanceStatus(e.status) {
			case smtypes.NotebookInstanceStatusStopped:
				finding = audit.Finding{
					Service:    "sagemaker",
					ResourceID: e.name,
					Check:      "stopped_notebook",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"type=%s, stopped but EBS storage still incurring cost",
						e.instanceType,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: monthlyCost * 0.1, // rough EBS-only estimate
					Remediation: remediation.Recommend(
						"cost",
						"sagemaker",
						"stopped_notebook",
						e.name,
						"notebook stopped but EBS still billed",
					),
				}
			case smtypes.NotebookInstanceStatusInService:
				finding = audit.Finding{
					Service:              "sagemaker",
					ResourceID:           e.name,
					Check:                "running_notebook",
					Status:               "PASS",
					Detail:               fmt.Sprintf("type=%s in service", e.instanceType),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: monthlyCost,
				}
			default:
				finding = audit.Finding{
					Service:    "sagemaker",
					ResourceID: e.name,
					Check:      "notebook_status",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"type=%s, status=%s",
						e.instanceType,
						e.status,
					),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: monthlyCost,
				}
			}

			mu.Lock()
			findings = append(findings, finding)
			mu.Unlock()
		}(name)
	}
	wg.Wait()

	return findings, nil
}
