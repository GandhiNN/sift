package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

func AuditBackupCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := backup.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)

	var findings []audit.Finding
	spinner := progress.NewSpinner(ctx, "Auditing Backup cost")

	retentionDays := t.GetInt("backup", "retention_days", 90)
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	// Check vaults for old recovery points
	vaultInput := &backup.ListBackupVaultsInput{}
	for {
		vaultResp, err := client.ListBackupVaults(ctx, vaultInput)
		if err != nil {
			spinner.Finish()
			return nil, fmt.Errorf("list backup vaults: %w", err)
		}
		for _, v := range vaultResp.BackupVaultList {
			vaultName := aws.ToString(v.BackupVaultName)

			rpInput := &backup.ListRecoveryPointsByBackupVaultInput{
				BackupVaultName: &vaultName,
			}
			var oldCount int
			var totalCount int
			for {
				rpResp, err := client.ListRecoveryPointsByBackupVault(ctx, rpInput)
				if err != nil {
					break
				}
				for _, rp := range rpResp.RecoveryPoints {
					totalCount++
					if rp.CreationDate != nil && rp.CreationDate.Before(cutoff) {
						oldCount++
					}
				}
				if rpResp.NextToken == nil {
					break
				}
				rpInput.NextToken = rpResp.NextToken
			}

			if oldCount > 0 {
				findings = append(findings, audit.Finding{
					Service:    "backup",
					ResourceID: vaultName,
					Check:      "old_recovery_points",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"total=%d, older_than_%dd=%d",
						totalCount,
						retentionDays,
						oldCount,
					),
					RiskLevel: "LOW",
					Remediation: remediation.Recommend(
						"cost",
						"backup",
						"old_recovery_points",
						vaultName,
						fmt.Sprintf("old_recovery_points=%d", oldCount),
					),
				})
			} else {
				findings = append(findings, audit.Finding{
					Service:    "backup",
					ResourceID: vaultName,
					Check:      "old_recovery_points",
					Status:     "PASS",
					Detail:     fmt.Sprintf("total=%d, all within %d day retention", totalCount, retentionDays),
					RiskLevel:  "MINIMAL",
				})
			}
		}
		spinner.Add(len(vaultResp.BackupVaultList))
		if vaultResp.NextToken == nil {
			break
		}
		vaultInput.NextToken = vaultResp.NextToken
	}
	spinner.Finish()

	return findings, nil
}
