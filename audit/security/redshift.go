package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
)

type redshiftSecurityEntry struct {
	id                 string
	publiclyAccessible bool
	encrypted          bool
	loggingEnabled     bool
	tags               map[string]string
}

func parseRedshiftSecurityEntry(
	ctx context.Context,
	client *redshift.Client,
	cluster *redshift.DescribeClustersOutput,
) []redshiftSecurityEntry {
	var entries []redshiftSecurityEntry
	for _, c := range cluster.Clusters {
		tags := make(map[string]string, len(c.Tags))
		for _, t := range c.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}

		loggingResp, _ := client.DescribeLoggingStatus(ctx, &redshift.DescribeLoggingStatusInput{
			ClusterIdentifier: c.ClusterIdentifier,
		})
		loggingEnabled := loggingResp != nil && aws.ToBool(loggingResp.LoggingEnabled)

		entries = append(entries, redshiftSecurityEntry{
			id:                 aws.ToString(c.ClusterIdentifier),
			publiclyAccessible: aws.ToBool(c.PubliclyAccessible),
			encrypted:          aws.ToBool(c.Encrypted),
			loggingEnabled:     loggingEnabled,
			tags:               tags,
		})
	}
	return entries
}

func redshiftRisk(publiclyAccessible, encrypted, loggingEnabled bool) string {
	switch {
	case publiclyAccessible && !encrypted:
		return "CRITICAL"
	case publiclyAccessible:
		return "HIGH"
	case !encrypted:
		return "HIGH"
	case !loggingEnabled:
		return "MEDIUM"
	default:
		return "MINIMAL"
	}
}

func AuditRedshift(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := redshift.NewFromConfig(cfg)

	var findings []audit.Finding
	input := &redshift.DescribeClustersInput{}
	paginator := redshift.NewDescribeClustersPaginator(client, input)

	bar := progress.NewSpinner(ctx, "Auditing Redshift security")
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			bar.Finish()
			return nil, fmt.Errorf("describe clusters: %w", err)
		}
		entries := parseRedshiftSecurityEntry(ctx, client, page)
		for _, e := range entries {
			risk := redshiftRisk(e.publiclyAccessible, e.encrypted, e.loggingEnabled)
			detail := fmt.Sprintf(
				"publicly_accessible=%t, encrypted=%t, logging=%t",
				e.publiclyAccessible, e.encrypted, e.loggingEnabled,
			)

			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend(
					"security",
					"redshift",
					"redshift_security",
					e.id,
					detail,
				)
			}

			findings = append(findings, audit.Finding{
				Service:     "redshift",
				ResourceID:  e.id,
				Tags:        e.tags,
				Check:       "redshift_security",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			})
		}
		bar.Add(len(entries))
	}
	bar.Finish()

	return findings, nil
}
