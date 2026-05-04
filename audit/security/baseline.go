package security

import (
	"context"
	"fmt"
	"sync"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

func AuditBaseline(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	var ctFindings, gdFindings []audit.Finding
	var ctErr, gdErr error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		ctFindings, ctErr = auditCloudTrail(ctx, cfg)
	}()
	go func() {
		defer wg.Done()
		gdFindings, gdErr = auditGuardDuty(ctx, cfg)
	}()
	wg.Wait()

	if ctErr != nil {
		return nil, fmt.Errorf("cloudtrail: %w", ctErr)
	}

	if gdErr != nil {
		return nil, fmt.Errorf("guardduty: %w", gdErr)
	}

	return append(ctFindings, gdFindings...), nil
}

func auditCloudTrail(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := cloudtrail.NewFromConfig(cfg)
	var findings []audit.Finding

	resp, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe trails: %w", err)
	}

	if len(resp.TrailList) == 0 {
		return []audit.Finding{{
			Service:   "cloudtrail",
			Check:     "no_trails",
			Status:    "FAIL",
			Detail:    "no CloudTrail trails configured",
			RiskLevel: "CRITICAL",
		}}, nil
	}

	for _, trail := range resp.TrailList {
		name := aws.ToString(trail.Name)

		status, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})
		if err != nil {
			continue
		}

		if !aws.ToBool(status.IsLogging) {
			findings = append(findings, audit.Finding{
				Service:    "cloudtrail",
				ResourceID: name,
				Check:      "logging_disabled",
				Status:     "FAIL",
				Detail:     "trail exists but logging is disabled",
				RiskLevel:  "CRITICAL",
			})
			continue
		}

		if !aws.ToBool(trail.IsMultiRegionTrail) {
			findings = append(findings, audit.Finding{
				Service:    "cloudtrail",
				ResourceID: name,
				Check:      "single_region",
				Status:     "FAIL",
				Detail:     "trail is not multi-region",
				RiskLevel:  "HIGH",
			})
		}

		if !aws.ToBool(trail.LogFileValidationEnabled) {
			findings = append(findings, audit.Finding{
				Service:    "cloudtrail",
				ResourceID: name,
				Check:      "no_log_validation",
				Status:     "FAIL",
				Detail:     "trail has no log file validation",
				RiskLevel:  "MEDIUM",
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, audit.Finding{
			Service:   "cloudtrail",
			Check:     "enabled",
			Status:    "PASS",
			Detail:    "CloudTrail is properly configured",
			RiskLevel: "MINIMAL",
		})
	}

	return findings, nil
}

func auditGuardDuty(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := guardduty.NewFromConfig(cfg)
	var findings []audit.Finding

	resp, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return nil, fmt.Errorf("list detectors: %w", err)
	}

	if len(resp.DetectorIds) == 0 {
		return []audit.Finding{{
			Service:   "guardduty",
			Check:     "not_enabled",
			Status:    "FAIL",
			Detail:    "GuardDuty is not enabled",
			RiskLevel: "CRITICAL",
		}}, nil
	}

	for _, id := range resp.DetectorIds {
		det, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{
			DetectorId: &id,
		})
		if err != nil {
			continue
		}

		if string(det.Status) != "ENABLED" {
			findings = append(findings, audit.Finding{
				Service:   "guardduty",
				Check:     "detector_disabled",
				Status:    "FAIL",
				Detail:    "detector is not enabled",
				RiskLevel: "CRITICAL",
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, audit.Finding{
			Service:   "guardduty",
			Check:     "enabled",
			Status:    "PASS",
			Detail:    "GuardDuty is enabled",
			RiskLevel: "MINIMAL",
		})
	}

	return findings, nil
}
