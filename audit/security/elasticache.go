package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
)

func init() {
	audit.Register(Module, audit.Checker{Name: "elasticache", Fn: AuditElastiCache})
}

type elasticacheSecurityEntry struct {
	id                string
	engine            string
	transitEncryption bool
	atRestEncryption  bool
	authTokenEnabled  bool
	autoMinorUpgrade  bool
}

func parseElasticCacheSecurityEntry(
	cluster *elasticache.DescribeCacheClustersOutput,
	idx int,
) elasticacheSecurityEntry {
	c := cluster.CacheClusters[idx]
	return elasticacheSecurityEntry{
		id:                aws.ToString(c.CacheClusterId),
		engine:            aws.ToString(c.Engine),
		transitEncryption: aws.ToBool(c.TransitEncryptionEnabled),
		atRestEncryption:  aws.ToBool(c.AtRestEncryptionEnabled),
		authTokenEnabled:  c.AuthTokenEnabled != nil && *c.AuthTokenEnabled,
		autoMinorUpgrade:  aws.ToBool(c.AutoMinorVersionUpgrade),
	}
}

func elasticacheRisk(transitEncryption, atRestEncryption, authTokenEnabled bool) string {
	switch {
	case !atRestEncryption && !transitEncryption && !authTokenEnabled:
		return "CRITICAL"
	case !atRestEncryption && !transitEncryption:
		return "HIGH"
	case !transitEncryption || !atRestEncryption:
		return "MEDIUM"
	case !authTokenEnabled:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

func AuditElastiCache(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := elasticache.NewFromConfig(cfg)

	type cacheEntry struct {
		id                string
		engine            string
		transitEncryption bool
		atRestEncryption  bool
		authTokenEnabled  bool
	}

	var entries []cacheEntry
	input := &elasticache.DescribeCacheClustersInput{}
	for {
		resp, err := client.DescribeCacheClusters(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe cache clusters: %w", err)
		}
		for _, c := range resp.CacheClusters {
			entries = append(entries, cacheEntry{
				id:                aws.ToString(c.CacheClusterId),
				engine:            aws.ToString(c.Engine),
				transitEncryption: aws.ToBool(c.TransitEncryptionEnabled),
				atRestEncryption:  aws.ToBool(c.AtRestEncryptionEnabled),
				authTokenEnabled:  c.AuthTokenEnabled != nil && *c.AuthTokenEnabled,
			})
		}
		if resp.Marker == nil {
			break
		}
		input.Marker = resp.Marker
	}

	results := audit.ProcessAll(
		ctx,
		entries,
		"Auditing ElastiCache security",
		func(_ context.Context, e cacheEntry) audit.Finding {
			risk := elasticacheRisk(e.transitEncryption, e.atRestEncryption, e.authTokenEnabled)
			detail := fmt.Sprintf(
				"engine=%s, transit_encryption=%t, at_rest_encryption=%t, auth_token=%t",
				e.engine, e.transitEncryption, e.atRestEncryption, e.authTokenEnabled,
			)

			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend(
					"security",
					"elasticache",
					"elasticache_security",
					e.id,
					detail,
				)
			}

			return audit.Finding{
				Service:     "elasticache",
				ResourceID:  e.id,
				Check:       "elasticache_security",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
		},
	)
	return results, nil
}
