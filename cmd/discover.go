package cmd

import (
	"fmt"
	"os"

	"sift/audit/discover"

	"github.com/spf13/cobra"
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover active AWS services and show sift coverage",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cfg, cancel, err := buildAWSConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		defer cancel()

		services, err := discover.Discover(ctx, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}

		fmt.Print(discover.FormatOutput(services))
	},
}

func init() {
	rootCmd.AddCommand(discoverCmd)
}
