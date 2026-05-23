package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

func AuditBackup(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := backup.NewFromConfig(cfg)

	var findings []audit.Finding
	spinner := progress.NewSpinner(ctx, "Auditing Backup vaults")

	// Check vaults
	vaultInput := &backup.ListBackupVaultsInput{}
	for {
		resp, err := client.ListBackupVaults(ctx, vaultInput)
		if err != nil {
			spinner.Finish()
			return nil, fmt.Errorf("list backup vaults: %w", err)
		}
		for _, v := range resp.BackupVaultList {
			name := aws.ToString(v.BackupVaultName)
			encrypted := v.EncryptionKeyArn != nil && *v.EncryptionKeyArn != ""

			risk := "MINIMAL"
			if !encrypted {
				risk = "HIGH"
			}

			detail := fmt.Sprintf(
				"encrypted=%t, recovery_points=%d",
				encrypted,
				v.NumberOfRecoveryPoints,
			)

			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend("security", "backup", "vault_security", name, detail)
			}

			findings = append(findings, audit.Finding{
				Service:     "backup",
				ResourceID:  name,
				Check:       "vault_security",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			})
		}
		spinner.Add(len(resp.BackupVaultList))
		if resp.NextToken == nil {
			break
		}
		vaultInput.NextToken = resp.NextToken
	}
	spinner.Finish()

	return findings, nil
}
