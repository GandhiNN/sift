package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
)

func init() {
	audit.Register(Module, audit.Checker{Name: "opensearch", Fn: AuditOpenSearch})
}

func opensearchRisk(publicAccess, encryptAtRest, nodeToNode, fineGrained bool) string {
	switch {
	case publicAccess && !encryptAtRest && !fineGrained:
		return "CRITICAL"
	case publicAccess && !fineGrained:
		return "HIGH"
	case publicAccess:
		return "MEDIUM"
	case !encryptAtRest || !nodeToNode:
		return "MEDIUM"
	case !fineGrained:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

func AuditOpenSearch(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := opensearch.NewFromConfig(cfg)

	resp, err := client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("list domain names: %w", err)
	}

	var names []string
	for _, d := range resp.DomainNames {
		names = append(names, aws.ToString(d.DomainName))
	}

	results := audit.ProcessAll(
		ctx,
		names,
		"Auditing OpenSearch security",
		func(ctx context.Context, name string) audit.Finding {
			desc, err := client.DescribeDomain(
				ctx,
				&opensearch.DescribeDomainInput{DomainName: &name},
			)
			if err != nil {
				return audit.ErrorFinding("opensearch", name, "opensearch_security", err)
			}

			domain := desc.DomainStatus
			encryptAtRest := domain.EncryptionAtRestOptions != nil &&
				aws.ToBool(domain.EncryptionAtRestOptions.Enabled)
			nodeToNode := domain.NodeToNodeEncryptionOptions != nil &&
				aws.ToBool(domain.NodeToNodeEncryptionOptions.Enabled)
			fineGrained := domain.AdvancedSecurityOptions != nil &&
				aws.ToBool(domain.AdvancedSecurityOptions.Enabled)
			vpcEnabled := domain.VPCOptions != nil && aws.ToString(domain.VPCOptions.VPCId) != ""
			publicAccess := !vpcEnabled

			risk := opensearchRisk(publicAccess, encryptAtRest, nodeToNode, fineGrained)
			detail := fmt.Sprintf(
				"public_access=%t, encrypt_at_rest=%t, node_to_node=%t, fine_grained_access=%t",
				publicAccess, encryptAtRest, nodeToNode, fineGrained,
			)

			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend(
					"security",
					"opensearch",
					"opensearch_security",
					name,
					detail,
				)
			}

			return audit.Finding{
				Service:     "opensearch",
				ResourceID:  name,
				Check:       "opensearch_security",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
		},
	)
	return results, nil
}
