package cost

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type rdsCostInstance struct {
	id     string
	engine string
	class  string
	status string
	tags   map[string]string
}

func parseRDSCostInstance(db rdstypes.DBInstance) rdsCostInstance {
	tags := make(map[string]string, len(db.TagList))
	for _, t := range db.TagList {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return rdsCostInstance{
		id:     aws.ToString(db.DBInstanceIdentifier),
		engine: aws.ToString(db.Engine),
		class:  aws.ToString(db.DBInstanceClass),
		status: aws.ToString(db.DBInstanceStatus),
		tags:   tags,
	}
}

func AuditRDSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	rdsClient := rds.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	var findings []audit.Finding

	var allDBs []rdstypes.DBInstance
	paginator := rds.NewDescribeDBInstancesPaginator(rdsClient, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe db instances: %w", err)
		}
		allDBs = append(allDBs, page.DBInstances...)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for _, db := range allDBs {
		r := parseRDSCostInstance(db)

		if r.status == "stopped" {
			findings = append(findings, audit.Finding{
				Service:    "rds",
				ResourceID: r.id,
				Tags:       r.tags,
				Check:      "stopped_instance",
				Status:     "WARN",
				Detail: fmt.Sprintf(
					"engine=%s, storage still incurring cost",
					r.engine,
				),
				RiskLevel:            "MEDIUM",
				EstimatedMonthlyCost: pricing.RDSMonthly(r.class),
			})
			continue
		}

		if r.status != "available" {
			continue
		}

		wg.Add(1)
		go func(r rdsCostInstance) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			avgCPU, err := getAvgCPU(ctx, cwClient, r.id)
			if err != nil {
				mu.Lock()
				findings = append(findings, audit.ErrorFinding("rds", r.id, "check_cpu", err))
				mu.Unlock()
				return
			}
			t := audit.GetThresholds(ctx)
			if avgCPU < audit.GetThresholds(ctx).
				GetFloat("rds", "cpu_idle_percent", t.CPUIdlePercent) {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:    "rds",
					ResourceID: r.id,
					Tags:       r.tags, Check: "oversized_instance",
					Status: "WARN",
					Detail: fmt.Sprintf(
						"class=%s, avg CPU=%.1f%% over %d days, consider downsizing",
						r.class,
						avgCPU,
						audit.GetThresholds(ctx).GetInt("rds", "cpu_lookback_days", 7),
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: pricing.RDSMonthly(r.class),
					Remediation: remediation.Recommend(
						"rds",
						"oversized_instance",
						r.id,
						fmt.Sprintf("avg CPU %.1f%%", avgCPU),
					),
				})
				mu.Unlock()
			} else {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:    "rds",
					ResourceID: r.id,
					Tags:       r.tags,
					Check:      "oversized_instance",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"class=%s, avg CPU=%.1f%% over %d days",
						r.class,
						avgCPU,
						audit.GetThresholds(ctx).GetInt("rds", "cpu_lookback_days", 7),
					),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: pricing.RDSMonthly(r.class),
					Remediation:          nil,
				})
				mu.Unlock()
			}
		}(r)
	}
	wg.Wait()
	return findings, nil
}

func getAvgCPU(ctx context.Context, client *cloudwatch.Client, dbID string) (float64, error) {
	end := time.Now()
	lookbackDays := audit.GetThresholds(ctx).GetInt("rds", "cpu_lookback_days", 7)
	start := end.AddDate(0, 0, -lookbackDays)

	resp, err := client.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/RDS"),
		MetricName: aws.String("CPUUtilization"),
		Dimensions: []cwtypes.Dimension{{
			Name:  aws.String("DBInstanceIdentifier"),
			Value: &dbID,
		}},
		StartTime:  &start,
		EndTime:    &end,
		Period:     aws.Int32(86400),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	})
	if err != nil {
		return 0, err
	}

	if len(resp.Datapoints) == 0 {
		return 0, fmt.Errorf("no datapoints")
	}

	var total float64
	for _, dp := range resp.Datapoints {
		total += aws.ToFloat64(dp.Average)
	}
	return total / float64(len(resp.Datapoints)), nil
}
