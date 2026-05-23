package cost

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/progress"
	"sift/audit/remediation"

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

type dmsCostInstance struct {
	id      string
	arn     string
	class   string
	multiAZ bool
	tags    map[string]string
}

func parseDMSCostInstance(
	ctx context.Context,
	client *databasemigrationservice.Client,
	inst dmstypes.ReplicationInstance,
) dmsCostInstance {
	d := dmsCostInstance{
		id:      aws.ToString(inst.ReplicationInstanceIdentifier),
		arn:     aws.ToString(inst.ReplicationInstanceArn),
		class:   aws.ToString(inst.ReplicationInstanceClass),
		multiAZ: inst.MultiAZ,
	}
	tagResp, err := client.ListTagsForResource(
		ctx,
		&databasemigrationservice.ListTagsForResourceInput{
			ResourceArn: &d.arn,
		},
	)
	if err == nil {
		d.tags = make(map[string]string, len(tagResp.TagList))
		for _, t := range tagResp.TagList {
			d.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}
	return d
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

			d := parseDMSCostInstance(ctx, client, inst)

			var local []audit.Finding

			if taskCount[d.arn] == 0 {
				local = append(local, audit.Finding{
					Service:    "dms",
					ResourceID: d.id,
					Tags:       d.tags,
					Check:      "idle_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"class=%s, no replication tasks assigned",
						d.class,
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: pricing.DMSMonthly(d.class),
					Remediation: remediation.Recommend(
						"cost",
						"dms",
						"idle_instance",
						d.id,
						"no replication tasks assigned",
					),
				})
			} else if stoppedTasks[d.arn] == taskCount[d.arn] {
				local = append(local, audit.Finding{
					Service:              "dms",
					ResourceID:           d.id,
					Check:                "all_tasks_stopped",
					Status:               "WARN",
					Detail:               fmt.Sprintf("class=%s, all %d tasks stopped but instance running", d.class, stoppedTasks[d.arn]),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: pricing.DMSMonthly(d.class),
					Remediation: remediation.Recommend("cost",
						"dms", "all_tasks_stopped", d.id, fmt.Sprintf("all %d tasks stopped", stoppedTasks[d.arn])),
				})
			}

			for _, prefix := range dmsPrevGenPrefixes {
				if strings.HasPrefix(d.class, prefix) {
					local = append(local, audit.Finding{
						Service:    "dms",
						ResourceID: d.id,
						Tags:       d.tags,
						Check:      "previous_gen_instance",
						Status:     "WARN",
						Detail: fmt.Sprintf(
							"class=%s, consider upgrading to current gen",
							d.class,
						),
						RiskLevel:            "LOW",
						EstimatedMonthlyCost: pricing.DMSMonthly(d.class),
						Remediation: remediation.Recommend(
							"cost",
							"dms",
							"all_tasks_stopped",
							d.id,
							fmt.Sprintf("all %d tasks stopped", stoppedTasks[d.arn]),
						),
					})
					break
				}
			}

			if d.multiAZ {
				local = append(local, audit.Finding{
					Service:    "dms",
					ResourceID: d.id,
					Tags:       d.tags,
					Check:      "multi_az",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"class=%s, Multi-AZ enabled (2x instance cost)",
						d.class,
					),
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: pricing.DMSMonthly(d.class),
					Remediation: remediation.Recommend(
						"cost",
						"dms",
						"multi_a",
						d.id,
						"Multi-AZ enabled, 2x cost",
					),
				})
			}

			avgCPU, err := getDMSAvgCPU(ctx, cwClient, d.id)
			if err == nil && avgCPU < t.GetFloat("dms", "cpu_idle_percent", t.CPUIdlePercent) {
				local = append(local, audit.Finding{
					Service:    "dms",
					ResourceID: d.id,
					Tags:       d.tags,
					Check:      "oversized_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"class=%s, avg CPU=%.1f%% over %d days, consider downsizing",
						d.class,
						avgCPU,
						t.GetInt("dms", "cpu_lookback_days", 7),
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: pricing.DMSMonthly(d.class),
					Remediation: remediation.Recommend(
						"cost",
						"dms",
						"oversized_instance",
						d.id,
						fmt.Sprintf("avg CPU %.1f%%", avgCPU),
					),
				})
			}

			if len(local) > 0 {
				mu.Lock()
				findings = append(findings, local...)
				mu.Unlock()
			} else {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:              "dms",
					ResourceID:           d.id,
					Tags:                 d.tags,
					Check:                "idle_instance",
					Status:               "PASS",
					Detail:               fmt.Sprintf("class=%s, active and right-sized", d.class),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: pricing.DMSMonthly(d.class),
					Remediation:          nil,
				})
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
	lookbackDays := audit.GetThresholds(ctx).GetInt("dms", "cpu_lookback_days", 7)
	start := end.AddDate(0, 0, -lookbackDays)

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
