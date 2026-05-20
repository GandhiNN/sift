package ops

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
)

const (
	defaultTableVersionLimit = 1_000_000
	glueServiceCode          = "glue"
)

type tableVersionCount struct {
	db    string
	table string
	count int64
}

func auditTableVersions(
	ctx context.Context,
	client *glue.Client,
	cfg aws.Config,
) ([]audit.Finding, error) {
	limit := getTableVersionLimit(ctx, cfg)

	spinner := progress.NewSpinner(ctx, "Collecting Glue tables")

	// Get all databases first
	var dbNames []string
	dbInput := &glue.GetDatabasesInput{}
	for {
		dbResp, err := client.GetDatabases(ctx, dbInput)
		if err != nil {
			return nil, fmt.Errorf("get databases: %w", err)
		}
		for _, db := range dbResp.DatabaseList {
			dbNames = append(dbNames, aws.ToString(db.Name))
		}
		if dbResp.NextToken == nil {
			break
		}
		dbInput.NextToken = dbResp.NextToken
	}

	// Get tables per database concurrently, using VersionId as version count
	var tables []tableVersionCount
	var mu sync.Mutex
	var wg sync.WaitGroup
	concurrency := audit.GetThresholds(ctx).GetInt("glue", "table_version_concurrency", 50)
	sem := make(chan struct{}, concurrency)

	for _, dbName := range dbNames {
		wg.Add(1)
		go func(dbName string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tableInput := &glue.GetTablesInput{DatabaseName: &dbName}
			for {
				tableResp, err := client.GetTables(ctx, tableInput)
				if err != nil {
					break
				}
				mu.Lock()
				for _, t := range tableResp.TableList {
					var v int64
					if t.VersionId != nil {
						fmt.Sscanf(aws.ToString(t.VersionId), "%d", &v)
					}
					tables = append(tables, tableVersionCount{
						db:    dbName,
						table: aws.ToString(t.Name),
						count: v,
					})
				}
				mu.Unlock()
				spinner.Add(len(tableResp.TableList))
				if tableResp.NextToken == nil {
					break
				}
				tableInput.NextToken = tableResp.NextToken
			}
		}(dbName)
	}
	wg.Wait()
	spinner.Finish()

	// Calculate total and sort
	var total int64
	for _, t := range tables {
		total += t.count
	}

	sort.Slice(tables, func(i, j int) bool {
		return tables[i].count > tables[j].count
	})

	var findings []audit.Finding

	pct := float64(total) / float64(limit) * 100
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
				"total_table_versions=%d (estimated), limit=%d, usage=%.1f%%",
				total,
				limit,
				pct,
			),
			RiskLevel: risk,
		})
	} else {
		findings = append(findings, audit.Finding{
			Service:    "glue",
			ResourceID: "catalog",
			Check:      "table_version_limit",
			Status:     "PASS",
			Detail:     fmt.Sprintf("total_table_versions=%d (estimated), limit=%d, usage=%.1f%%", total, limit, pct),
			RiskLevel:  "MINIMAL",
		})
	}

	for _, t := range tables {
		if t.count == 0 {
			continue
		}
		pctContrib := float64(t.count) / float64(total) * 100
		findings = append(findings, audit.Finding{
			Service:    "glue",
			ResourceID: fmt.Sprintf("%s/%s", t.db, t.table),
			Check:      "table_version_contributor",
			Status:     "INFO",
			Detail:     fmt.Sprintf("versions=%d ,contribution=%.1f%%", t.count, pctContrib),
			RiskLevel:  "LOW",
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
			return defaultTableVersionLimit
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
	return defaultTableVersionLimit
}
