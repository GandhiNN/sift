package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/ops"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"
)

var opsServices string

var validOpsServices = map[string]bool{
	"glue": true,
}

var opsCmd = &cobra.Command{
	Use:   "ops",
	Short: "Audit operational risks and service limits",
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		ctx, configs, cancel, err := buildAWSConfigs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer cancel()
		var services []string
		if opsServices != "" {
			services = strings.Split(opsServices, ",")
			for _, s := range services {
				if !validOpsServices[s] {
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
				findings, err := ops.Audit(ctx, cfg, services)
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
	opsCmd.Flags().
		StringVar(&opsServices, "service", "", "Comma-separated services to audit (glue). Default: all")
	rootCmd.AddCommand(opsCmd)
}
