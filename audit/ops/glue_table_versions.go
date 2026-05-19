package ops

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

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
	spinner := progress.NewSpinner(ctx, "Counting Glue tables")

	// Collect all db/table pairs
	type tableRef struct {
		db    string
		table string
	}
	var refs []tableRef
	dbInput := &glue.GetDatabasesInput{}
	for {
		dbResp, err := client.GetDatabases(ctx, dbInput)
		if err != nil {
			return nil, fmt.Errorf("get databases: %w", err)
		}
		for _, db := range dbResp.DatabaseList {
			dbName := aws.ToString(db.Name)
			tableInput := &glue.GetTablesInput{DatabaseName: &dbName}
			for {
				tableResp, err := client.GetTables(ctx, tableInput)
				if err != nil {
					break
				}
				for _, t := range tableResp.TableList {
					refs = append(refs, tableRef{db: dbName, table: aws.ToString(t.Name)})
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
	}
	spinner.Finish()

	// Count versions per table concurrently
	bar := progress.NewBar(ctx, int64(len(refs)), "Counting table versions")
	results := make([]tableVersionCount, len(refs))
	var totalVersions atomic.Int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for i, ref := range refs {
		wg.Add(1)
		go func(i int, db, table string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer bar.Add(1)

			var count int64
			input := &glue.GetTableVersionsInput{
				DatabaseName: &db,
				TableName:    &table,
			}
			for {
				resp, err := client.GetTableVersions(ctx, input)
				if err != nil {
					break
				}
				count += int64(len(resp.TableVersions))
				if resp.NextToken == nil {
					break
				}
				input.NextToken = resp.NextToken
			}
			results[i] = tableVersionCount{db: db, table: table, count: count}
			totalVersions.Add(count)
		}(i, ref.db, ref.table)
	}
	wg.Wait()

	total := totalVersions.Load()

	sort.Slice(results, func(i, j int) bool {
		return results[i].count > results[j].count
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
				"total_table_versions=%d, limit=%d, usage=%.1f%%",
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
			Detail:     fmt.Sprintf("total_table_versions=%d, limit=%d, usage=%.1f%%", total, limit, pct),
			RiskLevel:  "MINIMAL",
		})
	}

	for _, t := range results {
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
