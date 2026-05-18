package security

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type secretEntry struct {
	name             string
	rotationEnabled  bool
	daysSinceRotated int
	tags             map[string]string
}

func parseSecretEntry(secret smtypes.SecretListEntry) secretEntry {
	s := secretEntry{
		name:             aws.ToString(secret.Name),
		rotationEnabled:  aws.ToBool(secret.RotationEnabled),
		daysSinceRotated: -1,
	}
	if secret.LastRotatedDate != nil {
		s.daysSinceRotated = int(time.Since(*secret.LastRotatedDate).Hours() / 24)
	}
	s.tags = make(map[string]string, len(secret.Tags))
	for _, t := range secret.Tags {
		s.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return s
}

func AuditSecrets(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := secretsmanager.NewFromConfig(cfg)
	var findings []audit.Finding

	var allSecrets []smtypes.SecretListEntry
	paginator := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		allSecrets = append(allSecrets, page.SecretList...)
	}

	bar := progress.NewBar(ctx, int64(len(allSecrets)), "Auditing secrets")
	t := audit.GetThresholds(ctx)

	for _, secret := range allSecrets {
		s := parseSecretEntry(secret)

		rotationOverdue := s.daysSinceRotated > t.GetInt(
			"secrets",
			"rotation_max_days",
			t.RotationMaxDays,
		)
		risk := secretsRisk(s.rotationEnabled, rotationOverdue, s.daysSinceRotated)

		detail := fmt.Sprintf("rotation_enabled=%t", s.rotationEnabled)
		if s.daysSinceRotated >= 0 {
			detail += fmt.Sprintf(", days_since_rotated=%d", s.daysSinceRotated)
		} else {
			detail += ", never_rotated=true"
		}

		findings = append(findings, audit.Finding{
			Service:    "secrets_manager",
			ResourceID: s.name,
			Tags:       s.tags,
			Check:      "secret_rotation",
			Status:     statusFromRisk(risk),
			Detail:     detail,
			RiskLevel:  risk,
		})
		bar.Add(1)
	}
	return findings, nil
}

func secretsRisk(rotationEnabled, rotationOverdue bool, daysSinceRotated int) string {
	switch {
	case !rotationEnabled && daysSinceRotated == -1:
		return "HIGH"
	case !rotationEnabled:
		return "MEDIUM"
	case rotationOverdue:
		return "MEDIUM"
	default:
		return "MINIMAL"
	}
}
