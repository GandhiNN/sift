package security

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

func AuditEKS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := eks.NewFromConfig(cfg)

	var allClusters []string
	input := &eks.ListClustersInput{}
	for {
		resp, err := client.ListClusters(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list clusters: %w", err)
		}
		allClusters = append(allClusters, resp.Clusters...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	results := make([]audit.Finding, 0, len(allClusters))
	bar := progress.NewBar(ctx, int64(len(allClusters)), "Auditing EKS clusters")

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, name := range allClusters {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer bar.Add(1)

			desc, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{
				Name: &name,
			})
			if err != nil {
				return
			}
			cluster := desc.Cluster

			publicEP := false
			privateEP := false

			if cluster.ResourcesVpcConfig != nil {
				publicEP = cluster.ResourcesVpcConfig.EndpointPublicAccess
				privateEP = cluster.ResourcesVpcConfig.EndpointPrivateAccess
			}

			secretsEnc := false
			for _, enc := range cluster.EncryptionConfig {
				for _, res := range enc.Resources {
					if res == "secrets" {
						secretsEnc = true
					}
				}
			}

			var logEnabled, logDisabled []string
			if cluster.Logging != nil {
				for _, ls := range cluster.Logging.ClusterLogging {
					for _, lt := range ls.Types {
						if aws.ToBool(ls.Enabled) {
							logEnabled = append(logEnabled, string(lt))
						} else {
							logDisabled = append(logDisabled, string(lt))
						}
					}
				}
			}

			// Risk assessment
			var risk string
			switch {
			case publicEP && !privateEP && !secretsEnc:
				risk = "CRITICAL"
			case publicEP && !privateEP:
				risk = "HIGH"
			case publicEP:
				risk = "MEDIUM"
			case !secretsEnc || len(logDisabled) > 0:
				risk = "LOW"
			default:
				risk = "MINIMAL"
			}

			detail := fmt.Sprintf(
				"version=%s, public_ep=%t, private_ep=%t, secrets_encrypted=%t",
				aws.ToString(cluster.Version),
				publicEP,
				privateEP,
				secretsEnc,
			)
			if len(logDisabled) > 0 {
				detail += fmt.Sprintf(", logging_disabled=%s", strings.Join(logDisabled, ";"))
			}
			mu.Lock()
			results = append(results, audit.Finding{
				Service:    "eks",
				ResourceID: name,
				Check:      "cluster_security",
				Status:     statusFromRisk(risk),
				Detail:     detail,
				RiskLevel:  risk,
			})
			mu.Unlock()
		}(name)
	}
	wg.Wait()
	return results, nil
}
