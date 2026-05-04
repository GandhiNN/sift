package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"

	"sift/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	profile    string
	format     string
	riskLevel  string
	region     string
	verbose    bool
	outputFile string
)

var rootCmd = &cobra.Command{
	Use:   "sift",
	Short: "AWS security and cost audit tool",
}

func SetVersion(version, commit, date string) {
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	rootCmd.PersistentFlags().StringVar(&profile, "profile", "default", "AWS profile name")
	rootCmd.PersistentFlags().
		StringVar(&format, "format", "", "Output format (json|csv|table). Default: table for terminal, json for pipes")
	rootCmd.PersistentFlags().
		StringVar(&riskLevel, "risk-level", "", "Minimum risk level to show (MINIMAL|LOW|MEDIUM|HIGH|CRITICAL)")
	rootCmd.PersistentFlags().
		StringVar(&region, "region", "", "AWS region(s), comma-separated or 'all' (default: profile region)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Show detailed log output")
	rootCmd.PersistentFlags().
		StringVarP(&outputFile, "output", "o", "", "Write results to file instead of stdout")
}

func buildAWSConfig() (context.Context, aws.Config) {
	if !verbose {
		slog.SetDefault(
			slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		)
	}

	if format == "" {
		if term.IsTerminal(int(os.Stdout.Fd())) {
			format = "table"
		} else {
			format = "json"
		}
	}
	if format != "json" && format != "csv" && format != "table" {
		fmt.Fprintf(os.Stderr, "Error: unknown format %q (use json, csv or table)\n", format)
		os.Exit(1)
	}
	if riskLevel != "" {
		valid := map[string]bool{
			"MINIMAL":  true,
			"LOW":      true,
			"MEDIUM":   true,
			"HIGH":     true,
			"CRITICAL": true,
		}
		if !valid[strings.ToUpper(riskLevel)] {
			fmt.Fprintf(
				os.Stderr,
				"Error: unknown risk level %q (use MINIMAL, LOW, MEDIUM, HIGH, or CRITICAL)\n",
				riskLevel,
			)
			os.Exit(1)
		}
	}

	// Signal-based context cancellation for graceful Ctrl+C shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	_ = cancel // cancelled on process exit or Ctrl+C

	cfg, err := config.BuildConfig(ctx, profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return ctx, cfg
}

func buildAWSConfigs() (context.Context, []aws.Config) {
	ctx, baseCfg := buildAWSConfig()

	if region == "" {
		return ctx, []aws.Config{baseCfg}
	}

	var regions []string
	if region == "all" {
		var err error
		regions, err = listEnabledRegions(ctx, baseCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing regions: %v\n", err)
			os.Exit(1)
		}
		slog.Info("scanning all enabled regions", "count", len(regions))
	} else {
		regions = strings.Split(region, ",")
	}

	var configs []aws.Config
	for _, r := range regions {
		cfg := baseCfg.Copy()
		cfg.Region = r
		configs = append(configs, cfg)
	}
	return ctx, configs
}

func listEnabledRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	client := ec2.NewFromConfig(cfg)
	resp, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false),
	})
	if err != nil {
		return nil, err
	}
	var regions []string
	for _, r := range resp.Regions {
		regions = append(regions, aws.ToString(r.RegionName))
	}
	return regions, nil
}
