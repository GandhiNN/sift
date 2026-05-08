package cost

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
)

var dmsPrevGenPrefixes = []string{
	"dms.c4.",
	"dms.r4.",
	"dms.t2.",
}

func AuditDMSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := databasemigrationservice.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)

	var instances []dmstypes.ReplicationInstance
	input := &databasemigrationservice.DescribeReplicationInstancesInput{}
	for {
		resp, err := client.DescribeReplicationInstances(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe replication instances: %w", err)
		}
		instances = append(instances, resp.ReplicationInstances...)
		if resp.Marker == nil {
			break
		}
		input.Marker = resp.Marker
	}

	var tasks []dmstypes.ReplicationTask
	taskInput := &databasemigrationservice.DescribeReplicationTasksInput{}
	for {
		resp, err := client.DescribeReplicationTasks(ctx, taskInput)
		if err != nil {
			break
		}
		tasks = append(tasks, resp.ReplicationTasks...)
		if resp.Marker == nil {
			break
		}
		taskInput.Marker = resp.Marker
	}

	// Map instance ARN -> task counts
	taskCount := make(map[string]int)
	stoppedTasks := make(map[string]int)
	for _, task := range tasks {
		arn := aws.ToString(task.ReplicationInstanceArn)
		taskCount[arn]++
		if aws.ToString(task.Status) == "stopped" {
			stoppedTasks[arn]++
		}
	}

	bar := progress.NewBar(ctx, int64(len(instances)), "Auditing DMS cost")
	var findings []audit.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, t.Concurrency)

	for _, inst := range instances {
		wg.Add(1)
		go func(inst dmstypes.ReplicationInstance) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer bar.Add(1)

			id := aws.ToString(inst.ReplicationInstanceIdentifier)
			arn := aws.ToString(inst.ReplicationInstanceArn)
			class := aws.ToString(inst.ReplicationInstanceClass)

			var local []audit.Finding

			if taskCount[arn] == 0 {
				local = append(local, audit.Finding{
					Service:    "dms",
					ResourceID: id,
					Check:      "idle_instance",
					Status:     "WARN",
					Detail:     fmt.Sprintf("class=%s, no replication tasks assigned", class),
					RiskLevel:  "HIGH",
				})
			} else if stoppedTasks[arn] == taskCount[arn] {
				local = append(local, audit.Finding{
					Service:    "dms",
					ResourceID: id,
					Check:      "all_tasks_stopped",
					Status:     "WARN",
					Detail:     fmt.Sprintf("class=%s, all %d tasks stopped but instance running", class, stoppedTasks[arn]),
					RiskLevel:  "MEDIUM",
				})
			}

			for _, prefix := range dmsPrevGenPrefixes {
				if strings.HasPrefix(class, prefix) {
					local = append(local, audit.Finding{
						Service:    "dms",
						ResourceID: id,
						Check:      "previous_gen_instance",
						Status:     "WARN",
						Detail: fmt.Sprintf(
							"class=%s, consider upgrading to current gen",
							class,
						),
						RiskLevel: "LOW",
					})
					break
				}
			}

			if inst.MultiAZ {
				local = append(local, audit.Finding{
					Service:    "dms",
					ResourceID: id,
					Check:      "multi_az",
					Status:     "INFO",
					Detail:     fmt.Sprintf("class=%s, Multi-AZ enabled (2x instance cost)", class),
					RiskLevel:  "LOW",
				})
			}

			avgCPU, err := getDMSAvgCPU(ctx, cwClient, id)
			if err == nil && avgCPU < t.CPUIdlePercent {
				local = append(local, audit.Finding{
					Service:    "dms",
					ResourceID: id,
					Check:      "oversized_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"class=%s, avg CPU=%.1f%% over 7 days, consider downsizing",
						class,
						avgCPU,
					),
					RiskLevel: "MEDIUM",
				})
			}

			if len(local) > 0 {
				mu.Lock()
				findings = append(findings, local...)
				mu.Unlock()
			}
		}(inst)
	}
	wg.Wait()

	return findings, nil
}

func getDMSAvgCPU(
	ctx context.Context,
	client *cloudwatch.Client,
	instanceID string,
) (float64, error) {
	end := time.Now()
	start := end.AddDate(0, 0, -7)

	resp, err := client.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/DMS"),
		MetricName: aws.String("CPUUtilization"),
		Dimensions: []cwtypes.Dimension{{
			Name:  aws.String("ReplicationInstanceIdentifier"),
			Value: &instanceID,
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
