package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
)

type backupVaultEntry struct {
	name           string
	encrypted      bool
	recoveryPoints int64
}

func parseBackupVaultEntry(v backuptypes.BackupVaultListMember) backupVaultEntry {
	return backupVaultEntry{
		name:           aws.ToString(v.BackupVaultName),
		encrypted:      v.EncryptionKeyArn != nil && *v.EncryptionKeyArn != "",
		recoveryPoints: v.NumberOfRecoveryPoints,
	}
}

func backupRisk(encrypted bool) string {
	if !encrypted {
		return "HIGH"
	}
	return "MINIMAL"
}

func AuditBackup(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := backup.NewFromConfig(cfg)

	var vaults []backuptypes.BackupVaultListMember
	input := &backup.ListBackupVaultsInput{}
	for {
		resp, err := client.ListBackupVaults(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list backup vaults: %w", err)
		}
		vaults = append(vaults, resp.BackupVaultList...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	// Check vaults
	results := make([]audit.Finding, len(vaults))
	bar := progress.NewBar(ctx, int64(len(vaults)), "Auditing Backup vaults")

	for i, v := range vaults {
		entry := parseBackupVaultEntry(v)
		risk := backupRisk(entry.encrypted)
		detail := fmt.Sprintf(
			"encrypted=%t, recovery_points=%d",
			entry.encrypted,
			entry.recoveryPoints,
		)

		var rem *audit.Remediation
		if risk != "MINIMAL" {
			rem = remediation.Recommend("security", "backup", "vault_security", entry.name, detail)
		}

		results[i] = audit.Finding{
			Service:     "backup",
			ResourceID:  entry.name,
			Check:       "vault_security",
			Status:      statusFromRisk(risk),
			Detail:      detail,
			RiskLevel:   risk,
			Remediation: rem,
		}
		bar.Add(1)
	}
	return results, nil
}
