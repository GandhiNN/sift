package cost

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
)

type redshiftCostEntry struct {
	id       string
	nodeType string
	numNodes int32
	status   string
	tags     map[string]string
}

func AuditRedshiftCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := redshift.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)

	var clusters []redshiftCostEntry
	input := &redshift.DescribeClustersInput{}
	paginator := redshift.NewDescribeClustersPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe clusters: %w", err)
		}
		for _, c := range page.Clusters {
			tags := make(map[string]string, len(c.Tags))
			for _, tag := range c.Tags {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			clusters = append(clusters, redshiftCostEntry{
				id:       aws.ToString(c.ClusterIdentifier),
				nodeType: aws.ToString(c.NodeType),
				numNodes: aws.ToInt32(c.NumberOfNodes),
				status:   aws.ToString(c.ClusterStatus),
				tags:     tags,
			})
		}
	}

	bar := progress.NewBar(ctx, int64(len(clusters)), "Auditing Redshift cost")
	var findings []audit.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, t.Concurrency)

	for _, c := range clusters {
		wg.Add(1)
		go func(c redshiftCostEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer bar.Add(1)

			lookback := t.GetInt("redshift", "cpu_lookback_days", 7)
			end := time.Now()
			start := end.AddDate(0, 0, -lookback)

			resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/Redshift"),
				MetricName: aws.String("CPUUtilization"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("ClusterIdentifier"),
					Value: &c.id,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
			})

			if err != nil || len(resp.Datapoints) == 0 {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:    "redshift",
					ResourceID: c.id,
					Tags:       c.tags,
					Check:      "idle_cluster",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"node_type=%s, nodes=%d, no CPU metrics available",
						c.nodeType,
						c.numNodes,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: pricing.RedshiftMonthly(c.nodeType, c.numNodes),
					Remediation: remediation.Recommend(
						"cost",
						"redshift",
						"idle_cluster",
						c.id,
						"no CPU metrics available",
					),
				})
				mu.Unlock()
				return
			}

			var total float64
			for _, dp := range resp.Datapoints {
				total += aws.ToFloat64(dp.Average)
			}
			avgCPU := total / float64(len(resp.Datapoints))

			cpuThreshold := t.GetFloat("redshift", "cpu_idle_percent", t.CPUIdlePercent)
			if avgCPU < cpuThreshold {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:    "redshift",
					ResourceID: c.id,
					Tags:       c.tags,
					Check:      "oversized_cluster",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"node_type=%s, nodes=%d, avg CPU=%.1f%% over %d days",
						c.nodeType,
						c.numNodes,
						avgCPU,
						lookback,
					),
					RiskLevel: "HIGH",
					Remediation: remediation.Recommend(
						"cost",
						"redshift",
						"oversized_cluster",
						c.id,
						fmt.Sprintf("avg CPU %.1f%%", avgCPU),
					),
				})
				mu.Unlock()
			} else {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:              "redshift",
					ResourceID:           c.id,
					Tags:                 c.tags,
					Check:                "oversized_cluster",
					Status:               "PASS",
					Detail:               fmt.Sprintf("node_type=%s, nodes=%d, avg CPU=%.1f%% over %d days", c.nodeType, c.numNodes, avgCPU, lookback),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: pricing.RedshiftMonthly(c.nodeType, c.numNodes),
					Remediation:          nil,
				})
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()

	return findings, nil
}
