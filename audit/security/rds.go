package security

import (
	"context"
	"fmt"
	"sync"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func AuditRDS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := rds.NewFromConfig(cfg)

	var instances []rdstypes.DBInstance
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe db instances: %w", err)
		}
		instances = append(instances, page.DBInstances...)
	}

	results := make([]audit.Finding, len(instances))
	bar := progress.NewBar(ctx, int64(len(instances)), "Auditing RDS instances")

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for i, db := range instances {
		wg.Add(1)
		go func(i int, db rdstypes.DBInstance) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			id := aws.ToString(db.DBInstanceIdentifier)
			public := aws.ToBool(db.PubliclyAccessible)
			encrypted := aws.ToBool(db.StorageEncrypted)
			multiAZ := aws.ToBool(db.MultiAZ)
			backup := aws.ToInt32(db.BackupRetentionPeriod)
			delProtect := aws.ToBool(db.DeletionProtection)
			autoUpgrade := aws.ToBool(db.AutoMinorVersionUpgrade)

			var risk string
			switch {
			case public && !encrypted:
				risk = "CRITICAL"
			case public:
				risk = "HIGH"
			case !encrypted:
				risk = "HIGH"
			case backup < 7 || !delProtect:
				risk = "MEDIUM"
			case !multiAZ || !autoUpgrade:
				risk = "LOW"
			default:
				risk = "MINIMAL"
			}

			results[i] = audit.Finding{
				Service:    "rds",
				ResourceID: id,
				Check:      "instance_security",
				Status:     statusFromRisk(risk),
				Detail: fmt.Sprintf(
					"engine=%s, public=%t, encrypted=%t, multi_az=%t, backup_days=%d, delete_protection=%t, auto_upgrade=%t",
					aws.ToString(db.Engine),
					public,
					encrypted,
					multiAZ,
					backup,
					delProtect,
					autoUpgrade,
				),
				RiskLevel: risk,
			}
			bar.Add(1)
		}(i, db)
	}

	wg.Wait()
	return results, nil
}
