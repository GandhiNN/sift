package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func init() {
	audit.Register(Module, audit.Checker{Name: "rds", Fn: AuditRDS})
}

type rdsInstance struct {
	id          string
	engine      string
	public      bool
	encrypted   bool
	multiAZ     bool
	backup      int32
	delProtect  bool
	autoUpgrade bool
	tags        map[string]string
}

func parseRDSInstance(db rdstypes.DBInstance) rdsInstance {
	tags := make(map[string]string, len(db.TagList))
	for _, t := range db.TagList {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return rdsInstance{
		id:          aws.ToString(db.DBInstanceIdentifier),
		engine:      aws.ToString(db.Engine),
		public:      aws.ToBool(db.PubliclyAccessible),
		encrypted:   aws.ToBool(db.StorageEncrypted),
		multiAZ:     aws.ToBool(db.MultiAZ),
		backup:      aws.ToInt32(db.BackupRetentionPeriod),
		delProtect:  aws.ToBool(db.DeletionProtection),
		autoUpgrade: aws.ToBool(db.AutoMinorVersionUpgrade),
		tags:        tags,
	}
}

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

	return audit.ProcessAll(
		ctx,
		instances,
		"Auditing RDS instances",
		func(ctx context.Context, db rdstypes.DBInstance) audit.Finding {
			inst := parseRDSInstance(db)
			risk := rdsRisk(
				inst.public,
				inst.encrypted,
				inst.backup,
				inst.delProtect,
				inst.multiAZ,
				inst.autoUpgrade,
				7,
			)

			detail := fmt.Sprintf(
				"engine=%s, public=%t, encrypted=%t, multi_az=%t, backup_days=%d, delete_protection=%t, auto_upgrade=%t",
				inst.engine,
				inst.public,
				inst.encrypted,
				inst.multiAZ,
				inst.backup,
				inst.delProtect,
				inst.autoUpgrade,
			)

			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend("security", "rds", "rds_security", inst.id, detail)
			}

			return audit.Finding{
				Service:     "rds",
				ResourceID:  inst.id,
				Tags:        inst.tags,
				Check:       "instance_security",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
		},
	), nil
}

func rdsRisk(
	public, encrypted bool,
	backup int32,
	delProtect, multiAZ, autoUpgrade bool,
	minBackupDays int,
) string {
	switch {
	case public && !encrypted:
		return "CRITICAL"
	case public:
		return "HIGH"
	case !encrypted:
		return "HIGH"
	case backup < int32(minBackupDays) || !delProtect:
		return "MEDIUM"
	case !multiAZ || !autoUpgrade:
		return "LOW"
	default:
		return "MINIMAL"
	}
}
