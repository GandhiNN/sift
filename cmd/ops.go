package cmd

import (
	"sift/audit/ops"

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
		runAudit(opsServices, validOpsServices, ops.Audit)
	},
}

func init() {
	opsCmd.Flags().
		StringVar(&opsServices, "service", "", "Comma-separated services to audit (glue). Default: all")
	rootCmd.AddCommand(opsCmd)
}
