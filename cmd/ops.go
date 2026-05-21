package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"sift/audit"
	"sift/audit/history"
	"sift/audit/ops"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"
)

var opsCheck string

var opsCmd = &cobra.Command{
	Use:   "ops",
	Short: "Audit operational risks and service limits",
}

var opsGlueCmd = &cobra.Command{
	Use:   "glue",
	Short: "Audit Glue operational risks",
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		ctx, cfg, cancel, err := buildAWSConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		defer cancel()

		if quiet {
			ctx = progress.WithQuiet(ctx, true)
		}

		if opsCheck != "" {
			ctx = audit.WithChecks(ctx, strings.Split(opsCheck, ","))
		}

		findings, err := ops.AuditGlueOps(ctx, aws.Config(cfg))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}

		for i := range findings {
			findings[i].Region = cfg.Region
		}

		if err := audit.OutputWithFilter(format, findings, riskLevel, sortBy, start, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}

		if !noSave {
			store, storeErr := history.NewStore()
			if storeErr == nil {
				store.Save(profile, "ops-glue", findings)
			}
		}

		if audit.HasHighRiskFindings(findings) {
			os.Exit(1)
		}
	},
}

func init() {
	opsGlueCmd.Flags().
		StringVar(&opsCheck, "check", "", "Comma-separated checks (table_versions,crawlers,job_versions)")
	opsCmd.AddCommand(opsGlueCmd)
	rootCmd.AddCommand(opsCmd)
}
