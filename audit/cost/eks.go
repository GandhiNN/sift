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
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

type eksCostNodegroup struct {
	cluster       string
	name          string
	instanceTypes []string
	desiredSize   int32
	tags          map[string]string
}

func parseEKSCostNodegroup(cluster string, ng *ekstypes.Nodegroup) eksCostNodegroup {
	n := eksCostNodegroup{
		cluster:       cluster,
		name:          aws.ToString(ng.NodegroupName),
		instanceTypes: ng.InstanceTypes,
		tags:          ng.Tags,
	}
	if ng.ScalingConfig != nil {
		n.desiredSize = aws.ToInt32(ng.ScalingConfig.DesiredSize)
	}
	return n
}

func AuditEKSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := eks.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	asgClient := autoscaling.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)

	var allClusters []string
	clusterInput := &eks.ListClustersInput{}
	for {
		resp, err := client.ListClusters(ctx, clusterInput)
		if err != nil {
			return nil, fmt.Errorf("list clusters: %w", err)
		}
		allClusters = append(allClusters, resp.Clusters...)
		if resp.NextToken == nil {
			break
		}
		clusterInput.NextToken = resp.NextToken
	}

	return audit.ProcessAllMulti(
		ctx,
		allClusters,
		"Auditing EKS cost",
		func(ctx context.Context, name string) []audit.Finding {
			desc, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
			var clusterTags map[string]string
			if err == nil {
				clusterTags = desc.Cluster.Tags
			}

			var allNodegroups []string
			ngInput := &eks.ListNodegroupsInput{ClusterName: &name}
			for {
				ngResp, err := client.ListNodegroups(ctx, ngInput)
				if err != nil {
					return []audit.Finding{audit.ErrorFinding("eks", name, "list_nodegroups", err)}
				}
				allNodegroups = append(allNodegroups, ngResp.Nodegroups...)
				if ngResp.NextToken == nil {
					break
				}
				ngInput.NextToken = ngResp.NextToken
			}
			if len(allNodegroups) == 0 {
				return []audit.Finding{{
					Service:              "eks",
					ResourceID:           name,
					Tags:                 clusterTags,
					Check:                "cluster_no_nodegroups",
					Status:               "WARN",
					Detail:               "paying for control plane ($0.10/hr) with no node groups",
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: pricing.EKSClusterMonthly(),
					Remediation: remediation.Recommend(
						"cost",
						"eks",
						"cluster_no_nodegroups",
						name,
						"no node groups attached",
					),
				}}
			}
			var results []audit.Finding
			for _, ngName := range allNodegroups {
				ngResp, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
					ClusterName:   &name,
					NodegroupName: &ngName,
				})
				if err != nil {
					results = append(
						results,
						audit.ErrorFinding(
							"eks_nodegroup",
							fmt.Sprintf("%s/%s", name, ngName),
							"describe_nodegroup",
							err,
						),
					)
					continue
				}
				n := parseEKSCostNodegroup(name, ngResp.Nodegroup)
				var nodeCost float64
				if len(n.instanceTypes) > 0 {
					nodeCost = pricing.EC2Monthly(n.instanceTypes[0])
				}
				var ngFindings []audit.Finding
				for _, iType := range n.instanceTypes {
					for _, prefix := range dmsPrevGenPrefixes {
						if strings.HasPrefix(iType, prefix) {
							ngFindings = append(ngFindings, audit.Finding{
								Service:    "eks_nodegroup",
								ResourceID: fmt.Sprintf("%s/%s", n.cluster, n.name),
								Tags:       n.tags,
								Check:      "previous_gen_node",
								Status:     "WARN",
								Detail: fmt.Sprintf(
									"type=%s, consider upgrading",
									iType,
								),
								RiskLevel:            "LOW",
								EstimatedMonthlyCost: nodeCost,
								Remediation: remediation.Recommend(
									"cost",
									"eks",
									"previous_gen_node",
									fmt.Sprintf("%s/%s", n.cluster, n.name),
									fmt.Sprintf("type=%s", iType),
								),
							})
							break
						}
					}
				}
				if n.desiredSize == 0 {
					ngFindings = append(ngFindings, audit.Finding{
						Service:              "eks_nodegroup",
						ResourceID:           fmt.Sprintf("%s/%s", n.cluster, n.name),
						Tags:                 n.tags,
						Check:                "empty_nodegroup",
						Status:               "WARN",
						Detail:               "desired size is 0, consider removing if unused",
						RiskLevel:            "MEDIUM",
						EstimatedMonthlyCost: nodeCost,
						Remediation: remediation.Recommend(
							"cost",
							"eks",
							"empty_nodegroup",
							fmt.Sprintf("%s/%s", n.cluster, n.name),
							"desired size is 0",
						),
					})
				}
				// Check if nodegroup is oversized (low CPU)
				if n.desiredSize > 0 && ngResp.Nodegroup.Resources != nil {
					for _, asg := range ngResp.Nodegroup.Resources.AutoScalingGroups {
						if asg.Name == nil {
							continue
						}
						asgResp, err := asgClient.DescribeAutoScalingGroups(
							ctx,
							&autoscaling.DescribeAutoScalingGroupsInput{
								AutoScalingGroupNames: []string{*asg.Name},
							},
						)
						if err != nil || len(asgResp.AutoScalingGroups) == 0 {
							continue
						}
						var instanceIDs []string
						for _, inst := range asgResp.AutoScalingGroups[0].Instances {
							if inst.InstanceId != nil {
								instanceIDs = append(instanceIDs, *inst.InstanceId)
							}
							if nodeCost == 0 && inst.InstanceType != nil {
								nodeCost = pricing.EC2Monthly(*inst.InstanceType)
							}
						}
						if len(instanceIDs) == 0 {
							continue
						}

						lookback := t.GetInt("eks", "cpu_lookback_days", 7)
						end := time.Now()
						start := end.AddDate(0, 0, -lookback)
						cpuThreshold := t.GetFloat("eks", "cpu_idle_percent", 10)

						var totalCPU float64
						var datapoints int
						for _, id := range instanceIDs {
							resp, err := cwClient.GetMetricStatistics(
								ctx,
								&cloudwatch.GetMetricStatisticsInput{
									Namespace:  aws.String("AWS/EC2"),
									MetricName: aws.String("CPUUtilization"),
									Dimensions: []cwtypes.Dimension{{
										Name:  aws.String("InstanceId"),
										Value: aws.String(id),
									}},
									StartTime:  &start,
									EndTime:    &end,
									Period:     aws.Int32(86400),
									Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
								},
							)
							if err != nil {
								continue
							}
							for _, dp := range resp.Datapoints {
								totalCPU += aws.ToFloat64(dp.Average)
								datapoints++
							}
						}
						if datapoints > 0 {
							avgCPU := totalCPU / float64(datapoints)
							if avgCPU < cpuThreshold {
								ngFindings = append(ngFindings, audit.Finding{
									Service:    "eks_nodegroup",
									ResourceID: fmt.Sprintf("%s/%s", n.cluster, n.name),
									Tags:       n.tags,
									Check:      "oversized_nodegroup",
									Status:     "WARN",
									Detail: fmt.Sprintf(
										"instances=%d, avg CPU=%.1f%% over %d days, consider smaller instance type",
										len(instanceIDs),
										avgCPU,
										lookback,
									),
									RiskLevel:            "HIGH",
									EstimatedMonthlyCost: nodeCost * float64(n.desiredSize),
									Remediation: remediation.Recommend(
										"cost",
										"eks",
										"oversized_nodegroup",
										fmt.Sprintf("%s/%s", n.cluster, n.name),
										fmt.Sprintf("avg CPU %.1f%%", avgCPU),
									),
								})
							}
						}
					}
				}
				if len(ngFindings) > 0 {
					results = append(results, ngFindings...)
				} else {
					results = append(results, audit.Finding{
						Service:              "eks_nodegroup",
						ResourceID:           fmt.Sprintf("%s/%s", n.cluster, n.name),
						Tags:                 n.tags,
						Check:                "nodegroup_cost",
						Status:               "PASS",
						Detail:               fmt.Sprintf("desired=%d, current-gen instances", n.desiredSize),
						RiskLevel:            "MINIMAL",
						EstimatedMonthlyCost: nodeCost,
					})
				}
			}
			return results
		},
	), nil
}
