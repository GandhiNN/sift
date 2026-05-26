package cost

import (
	"context"
	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const Module = "cost"

var PrevGenPrefixes = []string{
	"m1.",
	"m2.",
	"m3.",
	"m4.",
	"c1.",
	"c3.",
	"c4.",
	"r3.",
	"r4.",
	"i2.",
	"t1.",
	"t2.",
}

func init() {
	for _, c := range []audit.Checker{
		{Name: "ec2", Fn: AuditEC2Cost},
		{Name: "ebs", Fn: AuditEBSCost},
		{Name: "rds", Fn: AuditRDSCost},
		{Name: "s3", Fn: AuditS3Cost},
		{Name: "eks", Fn: AuditEKSCost},
		{Name: "network", Fn: AuditNetworkCost},
		{Name: "cloudwatch", Fn: AuditCloudwatchCost},
		{Name: "ecr", Fn: AuditECRCost},
		{Name: "secrets", Fn: AuditSecretsCost},
		{Name: "glue", Fn: AuditGlueCost},
		{Name: "lambda", Fn: AuditLambdaCost},
		{Name: "dynamodb", Fn: AuditDynamoDBCost},
		{Name: "dms", Fn: AuditDMSCost},
		{Name: "elb", Fn: AuditELBCost},
		{Name: "sagemaker", Fn: AuditSagemakerCost},
		{Name: "redshift", Fn: AuditRedshiftCost},
		{Name: "stepfunctions", Fn: AuditStepFunctionsCost},
		{Name: "backup", Fn: AuditBackupCost},
	} {
		audit.Register(Module, c)
	}
}

func Audit(ctx context.Context, cfg aws.Config, services []string) ([]audit.Finding, error) {
	return audit.RunChecks(ctx, cfg, services, audit.CheckersFor(Module), "Auditing cost waste")
}
