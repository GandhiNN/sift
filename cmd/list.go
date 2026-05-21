package cmd

import (
	"fmt"
	"os"
	"time"

	"sift/audit"
	"sift/audit/list"
	"sift/audit/progress"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List AWS resources with metadata",
}

var listGlueCmd = &cobra.Command{
	Use:   "glue [resource]",
	Short: "List Glue resources (jobs, crawlers)",
	Args:  cobra.MaximumNArgs(1),
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

		var resources []audit.Resource

		switch {
		case len(args) == 0:
			// List all
			jobs, err := list.ListGlueJobs(ctx, cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			resources = append(resources, jobs...)
			crawlers, err := list.ListGlueCrawlers(ctx, cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			resources = append(resources, crawlers...)
		case args[0] == "jobs":
			var err error
			resources, err = list.ListGlueJobs(ctx, cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
		case args[0] == "crawlers":
			var err error
			resources, err = list.ListGlueCrawlers(ctx, cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
		default:
			fmt.Fprintf(
				os.Stderr,
				"Error: unknown resource %q (available: jobs, crawlers)\n",
				args[0],
			)
			os.Exit(2)
		}

		for i := range resources {
			resources[i].Region = cfg.Region
		}

		if err := audit.OutputResources(format, resources, start, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
	},
}

func init() {
	listCmd.AddCommand(listGlueCmd)
	rootCmd.AddCommand(listCmd)
}
