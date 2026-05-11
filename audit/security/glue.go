package security

import (
	"context"
	"fmt"
	"sync"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
)

type glueJob struct {
	name      string
	role      string
	encrypted bool
	tags      map[string]string
}

func parseGlueJob(ctx context.Context, client *glue.Client, job gluetypes.Job) glueJob {
	g := glueJob{
		name: aws.ToString(job.Name),
		role: aws.ToString(job.Role),
	}
	if job.SecurityConfiguration != nil && *job.SecurityConfiguration != "" {
		g.encrypted = true
	}
	tagResp, err := client.GetTags(ctx, &glue.GetTagsInput{ResourceArn: job.Name})
	if err == nil {
		g.tags = tagResp.Tags
	}
	return g
}

func AuditGlue(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := glue.NewFromConfig(cfg)
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

		findings = append(findings, audit.Finding{
			Service:    "glue",
			ResourceID: "data_catalog",
			Check:      "catalog_encryption",
			Status:     statusFromRisk(risk),
			Detail: fmt.Sprintf(
				"catalog_encrypted=%t, connection_password_encrypted=%t",
				catalogEncrypted,
				connEncrypted,
			),
			RiskLevel: risk,
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

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for _, job := range allJobs {
		wg.Add(1)
		go func(job gluetypes.Job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			g := parseGlueJob(ctx, client, job)
			risk := "MINIMAL"
			if !g.encrypted {
				risk = "LOW"
			}
			mu.Lock()
			findings = append(findings, audit.Finding{
				Service:    "glue",
				ResourceID: g.name,
				Tags:       g.tags,
				Check:      "job_security",
				Status:     statusFromRisk(risk),
				Detail: fmt.Sprintf(
					"security_config=%t, role=%s",
					g.encrypted,
					g.role,
				),
				RiskLevel: risk,
			})
			mu.Unlock()
		}(job)
	}
	wg.Wait()

	// Check for dev endpoints (deprecated but may still exist)
	devResp, err := client.GetDevEndpoints(ctx, &glue.GetDevEndpointsInput{})
	if err == nil {
		for _, ep := range devResp.DevEndpoints {
			name := aws.ToString(ep.EndpointName)
			findings = append(findings, audit.Finding{
				Service:    "glue",
				ResourceID: name,
				Check:      "dev_endpoint",
				Status:     "FAIL",
				Detail: fmt.Sprintf(
					"status=%s, dev endpoints are deprecated and a security risk",
					aws.ToString(ep.Status),
				),
				RiskLevel: "HIGH",
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
