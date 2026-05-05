package cmd

import (
	"sift/audit/security"

	"github.com/spf13/cobra"
)

var securityServices string

var validSecurityServices = map[string]bool{
	"ec2": true, "sagemaker": true, "s3": true, "rds": true, "eks": true,
	"iam": true, "secrets": true, "glue": true, "baseline": true, "lambda": true,
}

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Audit AWS resource security posture",
	Run: func(cmd *cobra.Command, args []string) {
		runAudit(securityServices, validSecurityServices, security.Audit)
	},
}

func init() {
	securityCmd.Flags().
		StringVar(&securityServices, "service", "", "Comma-separated services to audit (ec2,sagemaker,s3,rds,eks,iam,baseline,secrets). Default: all")
	rootCmd.AddCommand(securityCmd)
}
