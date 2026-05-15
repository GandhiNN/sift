package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/progress"
	"sift/audit/security"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"
)

var (
	triageLogGroup string
	triageInstance string
)

var triageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Deep investigation: EC2 posture + IAM + flow logs",
	Run: func(cmd *cobra.Command, args []string) {
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
		var mu sync.Mutex
		var allResults []audit.Finding
		var wg sync.WaitGroup
		for _, cfg := range configs {
			slog.Info("scanning region", "region", cfg.Region)
			wg.Add(1)
			go func(cfg aws.Config) {
				defer wg.Done()
				slog.Info("scanning region", "region", cfg.Region)
				var targets []security.TriageTarget
				if triageInstance != "" {
					t, err := security.ListEC2TargetByID(ctx, cfg, triageInstance)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error in %s: %v\n", cfg.Region, err)
						return
					}
					targets = []security.TriageTarget{*t}
				} else {
					var err error
					targets, err = security.ListEC2Targets(ctx, cfg)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error in %s: %v\n", cfg.Region, err)
						return
					}
				}
				results, err := security.Triage(ctx, cfg, triageLogGroup, targets)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error in %s: %v\n", cfg.Region, err)
					return
				}

				// Baseline checks (CloudTrail/GuardDuty)
				baselineResults, err := security.AuditBaseline(ctx, cfg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Baseline check error in %s: %v\n", cfg.Region, err)
				} else {
					results = append(results, baselineResults...)
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
		if err := audit.OutputWithFilter(format, allResults, riskLevel, sortBy, start, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		if audit.HasHighRiskFindings(allResults) {
			os.Exit(1)
		}
	},
}

func init() {
	triageCmd.Flags().
		StringVar(&triageLogGroup, "log-group", "", "VPC flow log group name (required)")
	triageCmd.Flags().StringVar(&triageInstance, "instance", "", "Specific EC2 instance ID")
	triageCmd.MarkFlagRequired("log-group")
	rootCmd.AddCommand(triageCmd)
}
