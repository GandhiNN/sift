package ops

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
)

const (
	defaultCrawlerVersionLimit = 1_000_000
	glueServiceCode            = "glue"
)

func AuditGlueOps(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	glueClient := glue.NewFromConfig(cfg)

	versionLimit := getCrawlerVersionLimit(ctx, cfg)

	var allCrawlers []gluetypes.Crawler
	input := &glue.GetCrawlersInput{}
	for {
		resp, err := glueClient.GetCrawlers(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("get crawlers: %w", err)
		}
		allCrawlers = append(allCrawlers, resp.Crawlers...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	var mu sync.Mutex
	var findings []audit.Finding
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for _, c := range allCrawlers {
		wg.Add(1)
		go func(c gluetypes.Crawler) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			name := aws.ToString(c.Name)
			version := c.Version
			pct := float64(version) / float64(versionLimit) * 100

			var risk string
			switch {
			case pct >= 95:
				risk = "CRITICAL"
			case pct >= 80:
				risk = "HIGH"
			case pct >= 60:
				risk = "MEDIUM"
			default:
				return
			}

			mu.Lock()
			findings = append(findings, audit.Finding{
				Service:    "glue",
				ResourceID: name,
				Check:      "crawler_version_limit",
				Status:     "WARN",
				Detail: fmt.Sprintf(
					"version=%d, limit=%d, usage=%.1f%%",
					version, versionLimit, pct,
				),
				RiskLevel: risk,
			})
			mu.Unlock()
		}(c)
	}
	wg.Wait()

	return findings, nil
}

func getCrawlerVersionLimit(ctx context.Context, cfg aws.Config) int64 {
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
			if strings.Contains(name, "crawler") && strings.Contains(name, "version") {
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
