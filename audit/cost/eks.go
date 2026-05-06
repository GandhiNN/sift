package cost

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

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
				ngInput.NextToken = ngResp.NextToken
			}

			if len(allNodegroups) == 0 {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:    "eks",
					ResourceID: name,
					Check:      "cluster_no_nodegroups",
					Status:     "WARN",
					Detail:     "paying for control plane ($0.10/hr) with no node groups",
					RiskLevel:  "HIGH",
				})
				mu.Unlock()
				return
			}

			var ngWg sync.WaitGroup
			for _, ngName := range allNodegroups {
				ngWg.Add(1)
				go func(ngName string) {
					defer ngWg.Done()
					ng, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
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
						return
					}

					var ngFindings []audit.Finding
					for _, iType := range ng.Nodegroup.InstanceTypes {
						for _, prefix := range PrevGenPrefixes {
							if strings.HasPrefix(iType, prefix) {
								ngFindings = append(ngFindings, audit.Finding{
									Service:    "eks_nodegroup",
									ResourceID: fmt.Sprintf("%s/%s", name, ngName),
									Check:      "previous_gen_node",
									Status:     "WARN",
									Detail:     fmt.Sprintf("type=%s, consider upgrading", iType),
									RiskLevel:  "LOW",
								})
								break
							}
						}
					}

					if ng.Nodegroup.ScalingConfig != nil &&
						aws.ToInt32(ng.Nodegroup.ScalingConfig.DesiredSize) == 0 {
						ngFindings = append(ngFindings, audit.Finding{
							Service:    "eks_nodegroup",
							ResourceID: fmt.Sprintf("%s/%s", name, ngName),
							Check:      "empty_nodegroup",
							Status:     "WARN",
							Detail:     "desired size is 0, consider removing if unused",
							RiskLevel:  "MEDIUM",
						})
					}
					if len(ngFindings) > 0 {
						mu.Lock()
						findings = append(findings, ngFindings...)
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
