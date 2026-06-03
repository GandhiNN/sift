package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func init() {
	audit.Register(Module, audit.Checker{Name: "glue", Fn: AuditGlue})
}

type glueTagsAPI interface {
	GetTags(
		ctx context.Context,
		params *glue.GetTagsInput,
		optFns ...func(*glue.Options),
	) (*glue.GetTagsOutput, error)
}

type glueJob struct {
	name      string
	role      string
	encrypted bool
	tags      map[string]string
}

func parseGlueJob(
	ctx context.Context,
	client glueTagsAPI,
	job gluetypes.Job,
	region, accountID string,
) glueJob {
	g := glueJob{
		name: aws.ToString(job.Name),
		role: aws.ToString(job.Role),
	}
	if job.SecurityConfiguration != nil && *job.SecurityConfiguration != "" {
		g.encrypted = true
	}
	arn := fmt.Sprintf("arn:aws:glue:%s:%s:job/%s", region, accountID, g.name)
	tagResp, err := client.GetTags(ctx, &glue.GetTagsInput{ResourceArn: &arn})
	if err == nil {
		g.tags = tagResp.Tags
	}
	return g
}

func AuditGlue(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := glue.NewFromConfig(cfg)
	stsClient := sts.NewFromConfig(cfg)
	var accountID string
	if resp, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err == nil {
		accountID = aws.ToString(resp.Account)
	}
	region := cfg.Region
	var findings []audit.Finding

	// Check data catalog encryption
	encResp, err := client.GetDataCatalogEncryptionSettings(
		ctx,
		&glue.GetDataCatalogEncryptionSettingsInput{},
	)
	if err == nil && encResp.DataCatalogEncryptionSettings != nil {
		enc := encResp.DataCatalogEncryptionSettings

		catalogEncrypted := enc.EncryptionAtRest != nil &&
			string(enc.EncryptionAtRest.CatalogEncryptionMode) != "DISABLED"
		connEncrypted := enc.ConnectionPasswordEncryption != nil &&
			enc.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted

		risk := glueCatalogRisk(catalogEncrypted, connEncrypted)

		detail := fmt.Sprintf(
			"catalog_encrypted=%t, connection_password_encrypted=%t",
			catalogEncrypted,
			connEncrypted,
		)

		var rem *audit.Remediation
		if risk != "MINIMAL" {
			rem = remediation.Recommend("security", "glue", "glue_security", "data_catalog", detail)
		}

		findings = append(findings, audit.Finding{
			Service:     "glue",
			ResourceID:  "data_catalog",
			Check:       "catalog_encryption",
			Status:      statusFromRisk(risk),
			Detail:      detail,
			RiskLevel:   risk,
			Remediation: rem,
		})
	}

	// Check job security settings
	var allJobs []gluetypes.Job
	jobInput := &glue.GetJobsInput{}
	for {
		jobsResp, err := client.GetJobs(ctx, jobInput)
		if err != nil {
			findings = append(findings, audit.ErrorFinding("glue", "jobs", "list_jobs", err))
			break
		}
		allJobs = append(allJobs, jobsResp.Jobs...)
		if jobsResp.NextToken == nil {
			break
		}
		jobInput.NextToken = jobsResp.NextToken
	}

	jobFindings := audit.ProcessAll(
		ctx,
		allJobs,
		"Auditing Glue job security",
		func(ctx context.Context, job gluetypes.Job) audit.Finding {
			g := parseGlueJob(ctx, client, job, region, accountID)
			risk := "MINIMAL"
			if !g.encrypted {
				risk = "LOW"
			}
			detail := fmt.Sprintf("security_config=%t, role=%s", g.encrypted, g.role)
			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend("security", "glue", "glue_security", g.name, detail)
			}
			return audit.Finding{
				Service:     "glue",
				ResourceID:  g.name,
				Tags:        g.tags,
				Check:       "job_security",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
		},
	)
	findings = append(findings, jobFindings...)

	// Check for dev endpoints (deprecated but may still exist)
	devResp, err := client.GetDevEndpoints(ctx, &glue.GetDevEndpointsInput{})
	if err == nil {
		for _, ep := range devResp.DevEndpoints {
			name := aws.ToString(ep.EndpointName)
			detail := fmt.Sprintf(
				"status=%s, dev endpoints are deprecated and a security risk",
				aws.ToString(ep.Status),
			)
			findings = append(findings, audit.Finding{
				Service:    "glue",
				ResourceID: name,
				Check:      "dev_endpoint",
				Status:     "FAIL",
				Detail:     detail,
				RiskLevel:  "HIGH",
				Remediation: remediation.Recommend(
					"security",
					"glue",
					"glue_security",
					name,
					"dev endpoints are deprecated",
				),
			})
		}
	}
	return findings, nil
}

func glueCatalogRisk(catalogEncrypted, connEncrypted bool) string {
	if !catalogEncrypted && !connEncrypted {
		return "HIGH"
	}
	if !catalogEncrypted || !connEncrypted {
		return "MEDIUM"
	}
	return "MINIMAL"
}
