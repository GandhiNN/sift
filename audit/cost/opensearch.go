package cost

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
)

var opensearchPrevGen = []string{"m4.", "r4.", "i2.", "t2.", "m3.", "r3."}

func init() {
	audit.Register(Module, audit.Checker{Name: "opensearch", Fn: AuditOpenSearchCost})
}

func AuditOpenSearchCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := opensearch.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)

	resp, err := client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("list domain names: %w", err)
	}

	var names []string
	for _, d := range resp.DomainNames {
		names = append(names, aws.ToString(d.DomainName))
	}

	lookback := t.GetInt("opensearch", "cpu_lookback_days", 7)
	cpuThreshold := t.GetFloat("opensearch", "cpu_idle_percent", 10)
	end := time.Now()
	start := end.AddDate(0, 0, -lookback)

	return audit.ProcessAllMulti(
		ctx,
		names,
		"Auditing OpenSearch cost",
		func(ctx context.Context, name string) []audit.Finding {
			desc, err := client.DescribeDomain(
				ctx,
				&opensearch.DescribeDomainInput{DomainName: &name},
			)
			if err != nil {
				return []audit.Finding{
					audit.ErrorFinding("opensearch", name, "describe_domain", err),
				}
			}

			domain := desc.DomainStatus
			instanceType := string(domain.ClusterConfig.InstanceType)
			instanceCount := aws.ToInt32(domain.ClusterConfig.InstanceCount)

			var results []audit.Finding

			// Check CPU
			cpuResp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/ES"),
				MetricName: aws.String("CPUUtilization"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("DomainName"),
					Value: &name,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
			})

			var avgCPU float64
			hasMetrics := false
			if cpuResp != nil && len(cpuResp.Datapoints) > 0 {
				hasMetrics = true
				var total float64
				for _, dp := range cpuResp.Datapoints {
					total += aws.ToFloat64(dp.Average)
				}
				avgCPU = total / float64(len(cpuResp.Datapoints))
			}

			// Check search rate
			searchResp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/ES"),
				MetricName: aws.String("SearchRate"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("DomainName"),
					Value: &name,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})

			var totalSearches float64
			if searchResp != nil {
				for _, dp := range searchResp.Datapoints {
					totalSearches += aws.ToFloat64(dp.Sum)
				}
			}

			if totalSearches == 0 && hasMetrics && avgCPU < cpuThreshold {
				monthlyCost := pricing.OpenSearchMonthly(instanceType, instanceCount)
				results = append(results, audit.Finding{
					Service:    "opensearch",
					ResourceID: name,
					Check:      "idle_domain",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"type=%s, nodes=%d, zero searches and avg CPU=%.1f%% over %d days",
						instanceType,
						instanceCount,
						avgCPU,
						lookback,
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"opensearch",
						"idle_domain",
						name,
						"zero searches and low CPU",
					),
				})
			} else if hasMetrics && avgCPU < cpuThreshold {
				monthlyCost := pricing.OpenSearchMonthly(instanceType, instanceCount)
				results = append(results, audit.Finding{
					Service:              "opensearch",
					ResourceID:           name,
					Check:                "oversized_domain",
					Status:               "WARN",
					Detail:               fmt.Sprintf("type=%s, nodes=%d, avg CPU=%.1f%% over %d days, consider downsizing", instanceType, instanceCount, avgCPU, lookback),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: monthlyCost,
					Remediation:          remediation.Recommend("cost", "opensearch", "oversized_domain", name, fmt.Sprintf("avg CPU %.1f%%", avgCPU)),
				})
			}

			// Previous gen check
			for _, prefix := range opensearchPrevGen {
				if strings.Contains(instanceType, prefix) {
					results = append(results, audit.Finding{
						Service:    "opensearch",
						ResourceID: name,
						Check:      "previous_gen_instance",
						Status:     "WARN",
						Detail: fmt.Sprintf(
							"type=%s, consider upgrading to current gen",
							instanceType,
						),
						RiskLevel: "LOW",
						Remediation: remediation.Recommend(
							"cost",
							"opensearch",
							"previous_gen_instance",
							name,
							"previous-gen instance type",
						),
					})
					break
				}
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "opensearch",
					ResourceID: name,
					Check:      "opensearch_cost",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"type=%s, nodes=%d, active",
						instanceType,
						instanceCount,
					),
					RiskLevel: "MINIMAL",
				})
			}

			return results
		},
	), nil
}
