package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
)

func init() {
	audit.Register(Module, audit.Checker{Name: "dms", Fn: AuditDMS})
}

type dmsSecurityEntry struct {
	id                 string
	publiclyAccessible bool
	encrypted          bool
	multiAZ            bool
}

func parseDMSSecurityEntry(inst dmstypes.ReplicationInstance) dmsSecurityEntry {
	encrypted := false
	if inst.KmsKeyId != nil && *inst.KmsKeyId != "" {
		encrypted = true
	}
	return dmsSecurityEntry{
		id:                 aws.ToString(inst.ReplicationInstanceIdentifier),
		publiclyAccessible: aws.ToBool(&inst.PubliclyAccessible),
		encrypted:          encrypted,
		multiAZ:            inst.MultiAZ,
	}
}

func dmsRisk(publiclyAccessible, encrypted bool) string {
	switch {
	case publiclyAccessible && !encrypted:
		return "CRITICAL"
	case publiclyAccessible:
		return "HIGH"
	case !encrypted:
		return "HIGH"
	default:
		return "MINIMAL"
	}
}

func AuditDMS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := databasemigrationservice.NewFromConfig(cfg)

	var instances []dmstypes.ReplicationInstance
	input := &databasemigrationservice.DescribeReplicationInstancesInput{}
	for {
		resp, err := client.DescribeReplicationInstances(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe replication instances: %w", err)
		}
		instances = append(instances, resp.ReplicationInstances...)
		if resp.Marker == nil {
			break
		}
		input.Marker = resp.Marker
	}

	results := audit.ProcessAll(
		ctx,
		instances,
		"Auditing DMS security",
		func(_ context.Context, inst dmstypes.ReplicationInstance) audit.Finding {
			d := parseDMSSecurityEntry(inst)
			risk := dmsRisk(d.publiclyAccessible, d.encrypted)

			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend(
					"security",
					"dms",
					"dms_security",
					d.id,
					fmt.Sprintf(
						"publicly_accessible-%t, encrypted=%t",
						d.publiclyAccessible,
						d.encrypted,
					),
				)
			}

			return audit.Finding{
				Service:    "dms",
				ResourceID: d.id,
				Check:      "dms_security",
				Status:     statusFromRisk(risk),
				Detail: fmt.Sprintf(
					"publicly_accessible=%t, encrypted=%t, multi_az=%t",
					d.publiclyAccessible,
					d.encrypted,
					d.multiAZ,
				),
				RiskLevel:   risk,
				Remediation: rem,
			}
		},
	)

	return results, nil
}
