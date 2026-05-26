package security

import (
	"context"
	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const Module = "security"

type TriageTarget struct {
	ResourceID  string
	Service     string
	PrivateIP   *string
	RoleARN     *string
	OpenToWorld bool
	IMDSv1      bool
}

func statusFromRisk(risk string) string {
	if risk == "MINIMAL" {
		return "PASS"
	}
	return "FAIL"
}

func init() {
	for _, c := range []audit.Checker{
		{Name: "ec2", Fn: AuditEC2},
		{Name: "sagemaker", Fn: AuditSagemaker},
		{Name: "s3", Fn: AuditS3},
		{Name: "rds", Fn: AuditRDS},
		{Name: "eks", Fn: AuditEKS},
		{Name: "iam", Fn: AuditIAMHygiene},
		{Name: "secrets", Fn: AuditSecrets},
		{Name: "glue", Fn: AuditGlue},
		{Name: "lambda", Fn: AuditLambda},
		{Name: "dynamodb", Fn: AuditDynamoDB},
		{Name: "elb", Fn: AuditELB},
		{Name: "dms", Fn: AuditDMS},
		{Name: "ecr", Fn: AuditECR},
		{Name: "redshift", Fn: AuditRedshift},
		{Name: "stepfunctions", Fn: AuditStepFunctions},
		{Name: "backup", Fn: AuditBackup},
		{Name: "baseline", Fn: AuditBaseline},
	} {
		audit.Register(Module, c)
	}
}

func Audit(ctx context.Context, cfg aws.Config, services []string) ([]audit.Finding, error) {
	return audit.RunChecks(ctx, cfg, services, audit.CheckersFor(Module), "Running security audit")
}
