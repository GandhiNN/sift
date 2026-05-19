package cost

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
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

	var mu sync.Mutex
	var findings []audit.Finding
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for _, name := range allClusters {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Get cluster tags
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
					mu.Lock()
					findings = append(
						findings,
						audit.ErrorFinding("eks", name, "list_nodegroups", err),
					)
					mu.Unlock()
					break
				}
				allNodegroups = append(allNodegroups, ngResp.Nodegroups...)
				if ngResp.NextToken == nil {
					break
				}
				allNodegroups = append(allNodegroups, ngResp.Nodegroups...)
				if ngResp.NextToken == nil {
					break
				}
				ngInput.NextToken = ngResp.NextToken
			}

			if len(allNodegroups) == 0 {
				mu.Lock()
				findings = append(findings, audit.Finding{
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
				})
				mu.Unlock()
				return
			}

			var ngWg sync.WaitGroup
			for _, ngName := range allNodegroups {
				ngWg.Add(1)
				go func(ngName string) {
					defer ngWg.Done()
					ngResp, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
						ClusterName:   &name,
						NodegroupName: &ngName,
					})
					if err != nil {
						mu.Lock()
						findings = append(
							findings,
							audit.ErrorFinding(
								"eks_nodegroup",
								fmt.Sprintf("%s/%s", name, ngName),
								"describe_nodegroup",
								err,
							),
						)
						mu.Unlock()
						return
					}

					n := parseEKSCostNodegroup(name, ngResp.Nodegroup)
					var nodeCost float64
					if len(n.instanceTypes) > 0 {
						nodeCost = pricing.EC2Monthly(n.instanceTypes[0])
					}
					var ngFindings []audit.Finding

					for _, iType := range n.instanceTypes {
						for _, prefix := range PrevGenPrefixes {
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

					if len(ngFindings) > 0 {
						mu.Lock()
						findings = append(findings, ngFindings...)
						mu.Unlock()
					} else {
						mu.Lock()
						findings = append(findings, audit.Finding{
							Service:              "eks_nodegroup",
							ResourceID:           fmt.Sprintf("%s/%s", n.cluster, n.name),
							Tags:                 n.tags,
							Check:                "nodegroup_cost",
							Status:               "PASS",
							Detail:               fmt.Sprintf("desired=%d, current-gen instances", n.desiredSize),
							RiskLevel:            "MINIMAL",
							EstimatedMonthlyCost: nodeCost,
							Remediation:          nil,
						})
						mu.Unlock()
					}
				}(ngName)
			}
			ngWg.Wait()
		}(name)
	}
	wg.Wait()
	return findings, nil
}
