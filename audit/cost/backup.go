package cost

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
)

func AuditBackupCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := backup.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)

	retentionDays := t.GetInt("backup", "retention_days", 90)
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	// Collect all vaults first
	var vaults []backuptypes.BackupVaultListMember
	vaultInput := &backup.ListBackupVaultsInput{}
	for {
		vaultResp, err := client.ListBackupVaults(ctx, vaultInput)
		if err != nil {
			return nil, fmt.Errorf("list backup vaults: %w", err)
		}
		vaults = append(vaults, vaultResp.BackupVaultList...)
		if vaultResp.NextToken == nil {
			break
		}
		vaultInput.NextToken = vaultResp.NextToken
	}

	results := make([]audit.Finding, len(vaults))
	bar := progress.NewBar(ctx, int64(len(vaults)), "Auditing Backup cost")
	var wg sync.WaitGroup
	sem := make(chan struct{}, t.Concurrency)

	for i, v := range vaults {
		wg.Add(1)
		go func(i int, v backuptypes.BackupVaultListMember) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer bar.Add(1)

			vaultName := aws.ToString(v.BackupVaultName)

			rpInput := &backup.ListRecoveryPointsByBackupVaultInput{
				BackupVaultName: &vaultName,
			}
			var oldCount, totalCount int
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
				detail := fmt.Sprintf(
					"total=%d, older_than_%dd=%d",
					totalCount,
					retentionDays,
					oldCount,
				)
				results[i] = audit.Finding{
					Service:    "backup",
					ResourceID: vaultName,
					Check:      "old_recovery_points",
					Status:     "WARN",
					Detail:     detail,
					RiskLevel:  "LOW",
					Remediation: remediation.Recommend(
						"cost",
						"backup",
						"old_recovery_points",
						vaultName,
						fmt.Sprintf("old_recovery_points=%d", oldCount),
					),
				}
			} else {
				results[i] = audit.Finding{
					Service:    "backup",
					ResourceID: vaultName,
					Check:      "old_recovery_points",
					Status:     "PASS",
					Detail:     fmt.Sprintf("total=%d, all within %d day retention", totalCount, retentionDays),
					RiskLevel:  "MINIMAL",
				}
			}
		}(i, v)
	}
	wg.Wait()

	return results, nil
}
