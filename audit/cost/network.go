package cost

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/pricing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type natGatewayEntry struct {
	id   string
	tags map[string]string
}

func parseNATGateway(nat ec2types.NatGateway) natGatewayEntry {
	tags := make(map[string]string, len(nat.Tags))
	for _, t := range nat.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return natGatewayEntry{
		id:   aws.ToString(nat.NatGatewayId),
		tags: tags,
	}
}

func AuditNetworkCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	var findings []audit.Finding

	nat, err := findIdleNATGateways(ctx, cfg)
	if err == nil {
		findings = append(findings, nat...)
	}

	return findings, nil
}

func findIdleNATGateways(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	ec2Client := ec2.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	var allNATs []ec2types.NatGateway
	natPaginator := ec2.NewDescribeNatGatewaysPaginator(ec2Client, &ec2.DescribeNatGatewaysInput{})
	for natPaginator.HasMorePages() {
		page, err := natPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe nat gateways: %w", err)
		}
		allNATs = append(allNATs, page.NatGateways...)
	}

	end := time.Now()
	start := end.AddDate(0, 0, -7)

	var mu sync.Mutex
	var findings []audit.Finding
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for _, nat := range allNATs {
		if string(nat.State) != "available" {
			continue
		}
		n := parseNATGateway(nat)
		wg.Add(1)
		go func(n natGatewayEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			metricResp, err := cwClient.GetMetricStatistics(
				ctx,
				&cloudwatch.GetMetricStatisticsInput{
					Namespace:  aws.String("AWS/NATGateway"),
					MetricName: aws.String("BytesOutToDestination"),
					Dimensions: []cwtypes.Dimension{{
						Name:  aws.String("NatGatewayId"),
						Value: &n.id,
					}},
					StartTime:  &start,
					EndTime:    &end,
					Period:     aws.Int32(86400),
					Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
				},
			)
			if err != nil {
				mu.Lock()
				findings = append(
					findings,
					audit.ErrorFinding("nat_gateway", n.id, "check_traffic", err),
				)
				mu.Unlock()
				return
			}

			totalBytes := 0.0
			for _, dp := range metricResp.Datapoints {
				totalBytes += aws.ToFloat64(dp.Sum)
			}

			if totalBytes == 0 {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:              "nat_gateway",
					ResourceID:           n.id,
					Tags:                 n.tags,
					Check:                "idle_nat_gateway",
					Status:               "WARN",
					Detail:               "zero bytes processed in last 7 days (~$32/mo waste)",
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: pricing.NATGatewayMonthly(),
				})
				mu.Unlock()
			} else {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:              "nat_gateway",
					ResourceID:           n.id,
					Tags:                 n.tags,
					Check:                "idle_nat_gateway",
					Status:               "PASS",
					Detail:               fmt.Sprintf("%.2f GB processed in last 7 days", totalBytes/(1024*1024*1024)),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: pricing.NATGatewayMonthly(),
				})
				mu.Unlock()
			}
		}(n)
	}

	wg.Wait()
	return findings, nil
}
