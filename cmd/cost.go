package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/cost"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"
)

var costServices string

var validCostServices = map[string]bool{
	"ec2": true, "ebs": true, "rds": true, "s3": true, "eks": true,
	"network": true, "cloudwatch": true, "ecr": true, "secrets": true, "glue": true, "lambda": true,
}

var costCmd = &cobra.Command{
	Use:   "cost",
	Short: "Detect cost waste across AWS resources",
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		ctx, configs := buildAWSConfigs()
		var services []string
		if costServices != "" {
			services = strings.Split(costServices, ",")
			for _, s := range services {
				if !validCostServices[s] {
					fmt.Fprintf(os.Stderr, "Error: unknown service %q\n", s)
					os.Exit(1)
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
				slog.Info("scanning region", "region", cfg.Region)
				findings, err := cost.Audit(ctx, cfg, services)
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

		if err := audit.OutputWithFilter(format, allFindings, riskLevel, start, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if audit.HasHighRiskFindings(allFindings) {
			os.Exit(1)
		}
	},
}

func init() {
	costCmd.Flags().
		StringVar(&costServices, "service", "", "comma-separated services to audit (ec2,ebs,rds,s3,eks,network,cloudwatch,ecr,secrets). Default: all")
	rootCmd.AddCommand(costCmd)
}
