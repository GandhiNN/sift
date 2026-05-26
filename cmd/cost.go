package cmd

import (
	"sift/audit"
	"sift/audit/cost"

	"github.com/spf13/cobra"
)

var costServices string

var costCmd = &cobra.Command{
	Use:   "cost",
	Short: "Detect cost waste across AWS resources",
	Run: func(cmd *cobra.Command, args []string) {
		runAudit("cost", costServices, audit.ValidServices(cost.Module), cost.Audit)

	},
}

func init() {
	costCmd.Flags().
		StringVar(&costServices, "service", "", serviceUsage(audit.ValidServices(cost.Module)))
	rootCmd.AddCommand(costCmd)
}
