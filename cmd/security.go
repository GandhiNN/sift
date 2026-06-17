package cmd

import (
	"os"
	"sift/audit"
	"sift/audit/security"

	"github.com/spf13/cobra"
)

var securityServices string

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Audit AWS resource security posture",
	Run: func(cmd *cobra.Command, args []string) {
		runAudit("security", securityServices, audit.ValidServices(security.Module), security.Audit)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	},
}

func init() {
	securityCmd.Flags().
		StringVar(&securityServices, "service", "", serviceUsage(audit.ValidServices(security.Module)))
	rootCmd.AddCommand(securityCmd)
}
