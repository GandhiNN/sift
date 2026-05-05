package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/security"

	"github.com/spf13/cobra"

	"github.com/aws/aws-sdk-go-v2/aws"
)

var securityServices string

var validSecurityServices = map[string]bool{
	"ec2": true, "sagemaker": true, "s3": true, "rds": true, "eks": true,
	"iam": true, "secrets": true, "glue": true, "baseline": true, "lambda": true,
}

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Audit AWS resource security posture",
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		ctx, configs, cancel, err := buildAWSConfigs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer cancel()
		var services []string
		if securityServices != "" {
			services = strings.Split(securityServices, ",")
			for _, s := range services {
				if !validSecurityServices[s] {
					fmt.Fprintf(os.Stderr, "Error: unknown service %q\n", s)
					os.Exit(1)
				}
			}
		}
		var mu sync.Mutex
		var allResults []audit.Finding
		var wg sync.WaitGroup
		for _, cfg := range configs {
			slog.Info("scanning region", "region", cfg.Region)
			wg.Add(1)
			go func(cfg aws.Config) {
				defer wg.Done()
				slog.Info("scanning region", "region", cfg.Region)
				results, err := security.Audit(ctx, cfg, services)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error in %s: %v\n", cfg.Region, err)
					return
				}
				for i := range results {
					results[i].Region = cfg.Region
				}
				mu.Lock()
				allResults = append(allResults, results...)
				mu.Unlock()
			}(cfg)
		}
		wg.Wait()
		if err := audit.OutputWithFilter(format, allResults, riskLevel, start, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if audit.HasHighRiskFindings(allResults) {
			os.Exit(1)
		}
	},
}

func init() {
	securityCmd.Flags().
		StringVar(&securityServices, "service", "", "Comma-separated services to audit (ec2,sagemaker,s3,rds,eks,iam,baseline,secrets). Default: all")
	rootCmd.AddCommand(securityCmd)
}
