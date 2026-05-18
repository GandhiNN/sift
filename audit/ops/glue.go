package ops

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
)

const (
	defaultCrawlerVersionLimit = 1_000_000
	glueServiceCode            = "glue"
)

func AuditGlueOps(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	glueClient := glue.NewFromConfig(cfg)

	tableVersionLimit := getTableVersionLimit(ctx, cfg)
	spinner := progress.NewSpinner(ctx, "Counting Glue table versions")

	// Count total table version across all databases, track per resources
	type tableVersion struct {
		db      string
		table   string
		version int64
	}

	var totalTableVersions int64
	var tables []tableVersion
	var dbInput *glue.GetDatabasesInput = &glue.GetDatabasesInput{}
	for {
		dbResp, err := glueClient.GetDatabases(ctx, dbInput)
		if err != nil {
			return nil, fmt.Errorf("get databases: %w", err)
		}
		for _, db := range dbResp.DatabaseList {
			dbName := aws.ToString(db.Name)
			tableInput := &glue.GetTablesInput{DatabaseName: &dbName}
			for {
				tableResp, err := glueClient.GetTables(ctx, tableInput)
				if err != nil {
					break
				}
				for _, t := range tableResp.TableList {
					if t.VersionId != nil {
						// VersionId is the current version number of this table
						var v int64
						fmt.Sscanf(aws.ToString(t.VersionId), "%d", &v)
						totalTableVersions += v
						tables = append(
							tables,
							tableVersion{db: dbName, table: aws.ToString(t.Name), version: v},
						)
					}
				}
				if tableResp.NextToken == nil {
					break
				}
				tableInput.NextToken = tableResp.NextToken
			}
		}
		if dbResp.NextToken == nil {
			break
		}
		dbInput.NextToken = dbResp.NextToken
	}

	// Sort by version descending to find top contributors
	sort.Slice(tables, func(i, j int) bool {
		return tables[i].version > tables[j].version
	})

	spinner.Finish()
	var findings []audit.Finding

	// Total table version check
	pct := float64(totalTableVersions) / float64(tableVersionLimit) * 100
	var risk string
	switch {
	case pct >= 95:
		risk = "CRITICAL"
	case pct >= 80:
		risk = "HIGH"
	case pct >= 60:
		risk = "MEDIUM"
	}
	if risk != "" {
		findings = append(findings, audit.Finding{
			Service:    "glue",
			ResourceID: "catalog",
			Check:      "table_version_limit",
			Status:     "WARN",
			Detail: fmt.Sprintf(
				"total_table_versions=%d, limit=%d, usage=%.1f%%",
				totalTableVersions, tableVersionLimit, pct,
			),
			RiskLevel: risk,
		})
	} else {
		findings = append(findings, audit.Finding{
			Service:    "glue",
			ResourceID: "catalog",
			Check:      "table_version_limit",
			Status:     "PASS",
			Detail: fmt.Sprintf(
				"total_table_versions=%d, limit=%d, usage=%.1f%%",
				totalTableVersions, tableVersionLimit, pct,
			),
			RiskLevel: "MINIMAL",
		})
	}

	// Add all tables as individual findings
	for _, t := range tables {
		pctContrib := float64(t.version) / float64(totalTableVersions) * 100
		findings = append(findings, audit.Finding{
			Service:    "glue",
			ResourceID: fmt.Sprintf("%s/%s", t.db, t.table),
			Check:      "table_version_contributor",
			Status:     "INFO",
			Detail: fmt.Sprintf(
				"versions=%d, contribution=%.1f%%",
				t.version, pctContrib,
			),
			RiskLevel: "LOW",
		})
	}
	return findings, nil
}

func getTableVersionLimit(ctx context.Context, cfg aws.Config) int64 {
	sqClient := servicequotas.NewFromConfig(cfg)

	input := &servicequotas.ListServiceQuotasInput{
		ServiceCode: aws.String(glueServiceCode),
	}
	for {
		resp, err := sqClient.ListServiceQuotas(ctx, input)
		if err != nil {
			return defaultCrawlerVersionLimit
		}
		for _, q := range resp.Quotas {
			name := strings.ToLower(aws.ToString(q.QuotaName))
			if strings.Contains(name, "table") && strings.Contains(name, "version") {
				if q.Value != nil {
					return int64(*q.Value)
				}
			}
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	return defaultCrawlerVersionLimit
}
