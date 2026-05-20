package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"sift/audit"
	"sift/audit/list"
	"sift/audit/progress"

	"github.com/spf13/cobra"
)

var (
	listService  string
	listResource string
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List AWS resources with metadata",
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

		if listService == "" || listResource == "" {
			fmt.Fprintln(os.Stderr, "Error: --service and --resource are required")
			os.Exit(2)
		}

		key := listService + "/" + listResource
		fn, ok := list.Registry[key]
		if !ok {
			var available []string
			for k := range list.Registry {
				available = append(available, k)
			}
			fmt.Fprintf(
				os.Stderr,
				"Error: unknown resource %q. Available: %s\n",
				key,
				strings.Join(available, ", "),
			)
			os.Exit(2)
		}

		resources, err := fn(ctx, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
	listCmd.Flags().StringVar(&listService, "service", "", "Service to list (e.g. glue)")
	listCmd.Flags().
		StringVar(&listResource, "resource", "", "Resource type to list (e.g. jobs, crawlers)")
	rootCmd.AddCommand(listCmd)
}
