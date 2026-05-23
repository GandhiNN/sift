package cmd

import (
	"sift/audit/security"

	"github.com/spf13/cobra"
)

var securityServices string

var validSecurityServices = map[string]bool{
	"ec2":           true,
	"sagemaker":     true,
	"s3":            true,
	"rds":           true,
	"eks":           true,
	"iam":           true,
	"secrets":       true,
	"glue":          true,
	"lambda":        true,
	"dynamodb":      true,
	"elb":           true,
	"dms":           true,
	"ecr":           true,
	"redshift":      true,
	"stepfunctions": true,
	"backup":        true,
}

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Audit AWS resource security posture",
	Run: func(cmd *cobra.Command, args []string) {
		runAudit("security", securityServices, validSecurityServices, security.Audit)
	},
}

func init() {
	securityCmd.Flags().
		StringVar(&securityServices, "service", "", "Comma-separated services to audit (ec2,sagemaker,s3,rds,eks,iam,baseline,secrets,glue,lambda,dynamodb,elb,dms,ecr,redshift,stepfunctions). Default: all")
	rootCmd.AddCommand(securityCmd)
}
