package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

func AuditSecretsCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
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

	for _, secret := range allSecrets {
		name := aws.ToString(secret.Name)

		if secret.LastAccessedDate != nil {
			days := int(time.Since(*secret.LastAccessedDate).Hours() / 24)
			if days > audit.GetThresholds(ctx).UnusedDays {
				findings = append(findings, audit.Finding{
					Service:    "secrets_manager",
					ResourceID: name,
					Check:      "unused_secret",
					Status:     "WARN",
					Detail:     fmt.Sprintf("last accessed %d days ago ($0.40/mo)", days),
					RiskLevel:  "LOW",
				})
			}
		}
	}
	return findings, nil
}
