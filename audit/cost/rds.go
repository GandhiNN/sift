package cost

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

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
		id := aws.ToString(db.DBInstanceIdentifier)
		status := aws.ToString(db.DBInstanceStatus)

		if status == "stopped" {
			findings = append(findings, audit.Finding{
				Service:    "rds",
				ResourceID: id,
				Check:      "stopped_instance",
				Status:     "WARN",
				Detail: fmt.Sprintf(
					"engine=%s, storage still incurring cost",
					aws.ToString(db.Engine),
				),
				RiskLevel: "MEDIUM",
			})
			continue
		}

		if status != "available" {
			continue
		}

		instanceClass := aws.ToString(db.DBInstanceClass)
		wg.Add(1)
		go func(id, instanceClass string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			avgCPU, err := getAvgCPU(ctx, cwClient, id)
			if err != nil {
				mu.Lock()
				findings = append(findings, audit.ErrorFinding("rds", id, "check_cpu", err))
				mu.Unlock()
				return
			}
			if avgCPU < audit.GetThresholds(ctx).CPUIdlePercent {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:    "rds",
					ResourceID: id,
					Check:      "oversized_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"class=%s, avg CPU=%.1f%% over 7 days, consider downsizing",
						instanceClass,
						avgCPU,
					),
					RiskLevel: "HIGH",
				})
				mu.Unlock()
			}
		}(id, instanceClass)
	}
	wg.Wait()
	return findings, nil
}

func getAvgCPU(ctx context.Context, client *cloudwatch.Client, dbID string) (float64, error) {
	end := time.Now()
	start := end.AddDate(0, 0, -7)

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
