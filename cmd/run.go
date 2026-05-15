package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type auditFunc func(context.Context, aws.Config, []string) ([]audit.Finding, error)

func runAudit(serviceFlag string, validServices map[string]bool, fn auditFunc) {
	start := time.Now()
	ctx, configs, cancel, err := buildAWSConfigs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	defer cancel()

	if quiet {
		ctx = progress.WithQuiet(ctx, true)
	}

	var services []string
	if serviceFlag != "" {
		services = strings.Split(serviceFlag, ",")
		for _, s := range services {
			if !validServices[s] {
				fmt.Fprintf(os.Stderr, "Error: unknown service %q\n", s)
				os.Exit(2)
			}
		}
	}

	var mu sync.Mutex
	var allFindings []audit.Finding
	var wg sync.WaitGroup
	for _, cfg := range configs {
		slog.Info("scanning region", "region", cfg.Region)
		wg.Add(1)
		go func(cfg aws.Config) {
			defer wg.Done()
			findings, err := fn(ctx, cfg, services)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error in %s: %v\n", cfg.Region, err)
				return
			}
			for i := range findings {
				findings[i].Region = cfg.Region
			}
			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(cfg)
	}
	wg.Wait()

	if err := audit.OutputWithFilter(format, allFindings, riskLevel, sortBy, start, outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	if audit.HasHighRiskFindings(allFindings) {
		os.Exit(1)
	}
}
