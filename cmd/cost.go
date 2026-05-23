package cmd

import (
	"sift/audit/cost"

	"github.com/spf13/cobra"
)

var costServices string

var validCostServices = map[string]bool{
	"ec2":           true,
	"ebs":           true,
	"rds":           true,
	"s3":            true,
	"eks":           true,
	"network":       true,
	"cloudwatch":    true,
	"ecr":           true,
	"secrets":       true,
	"glue":          true,
	"lambda":        true,
	"dynamodb":      true,
	"dms":           true,
	"elb":           true,
	"sagemaker":     true,
	"redshift":      true,
	"stepfunctions": true,
	"backup":        true,
}

var costCmd = &cobra.Command{
	Use:   "cost",
	Short: "Detect cost waste across AWS resources",
	Run: func(cmd *cobra.Command, args []string) {
		runAudit("cost", costServices, validCostServices, cost.Audit)

	},
}

func init() {
	costCmd.Flags().
		StringVar(&costServices, "service", "", serviceUsage(validCostServices))
	rootCmd.AddCommand(costCmd)
}
