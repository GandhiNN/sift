package security

import (
	"context"
	"fmt"
	"strings"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

func init() {
	audit.Register(Module, audit.Checker{Name: "eks", Fn: AuditEKS})
}

type eksCluster struct {
	name        string
	version     string
	publicEP    bool
	privateEP   bool
	secretsEnc  bool
	logDisabled []string
	tags        map[string]string
}

func parseEKSCluster(cluster *ekstypes.Cluster) eksCluster {
	c := eksCluster{
		name:    aws.ToString(cluster.Name),
		version: aws.ToString(cluster.Version),
		tags:    cluster.Tags,
	}

	if cluster.ResourcesVpcConfig != nil {
		c.publicEP = cluster.ResourcesVpcConfig.EndpointPublicAccess
		c.privateEP = cluster.ResourcesVpcConfig.EndpointPrivateAccess
	}

	for _, enc := range cluster.EncryptionConfig {
		for _, res := range enc.Resources {
			if res == "secrets" {
				c.secretsEnc = true
			}
		}
	}

	if cluster.Logging != nil {
		for _, ls := range cluster.Logging.ClusterLogging {
			for _, lt := range ls.Types {
				if !aws.ToBool(ls.Enabled) {
					c.logDisabled = append(c.logDisabled, string(lt))
				}
			}
		}
	}

	return c
}

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

	results := audit.ProcessAll(
		ctx,
		allClusters,
		"Auditing EKS clusters",
		func(ctx context.Context, name string) audit.Finding {
			desc, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
			if err != nil {
				return audit.ErrorFinding("eks", name, "cluster_security", err)
			}

			c := parseEKSCluster(desc.Cluster)
			risk := eksRisk(c.publicEP, c.privateEP, c.secretsEnc, len(c.logDisabled) > 0)

			detail := fmt.Sprintf(
				"version=%s, public_ep=%t, private_ep=%t, secrets_encrypted=%t",
				c.version, c.publicEP, c.privateEP, c.secretsEnc,
			)
			if len(c.logDisabled) > 0 {
				detail += fmt.Sprintf(", logging_disabled=%s", strings.Join(c.logDisabled, ";"))
			}

			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend("security", "eks", "eks_security", c.name, detail)
			}

			return audit.Finding{
				Service:     "eks",
				ResourceID:  c.name,
				Tags:        c.tags,
				Check:       "cluster_security",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
		},
	)

	return results, nil
}

func eksRisk(publicEP, privateEP, secretsEnc, hasDisabledLogs bool) string {
	switch {
	case publicEP && !privateEP && !secretsEnc:
		return "CRITICAL"
	case publicEP && !privateEP:
		return "HIGH"
	case publicEP:
		return "MEDIUM"
	case !secretsEnc || hasDisabledLogs:
		return "LOW"
	default:
		return "MINIMAL"
	}
}
