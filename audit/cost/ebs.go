package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func AuditEBSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := ec2.NewFromConfig(cfg)
	var findings []audit.Finding

	// Unattached volumes
	volPaginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{{
			Name:   aws.String("status"),
			Values: []string{"available"},
		}},
	})
	for volPaginator.HasMorePages() {
		page, err := volPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe volumes: %w", err)
		}
		for _, vol := range page.Volumes {
			findings = append(findings, audit.Finding{
				Service:    "ebs",
				ResourceID: aws.ToString(vol.VolumeId),
				Check:      "unattached_volume",
				Status:     "WARN",
				Detail: fmt.Sprintf(
					"size=%dGB, type=%s",
					aws.ToInt32(vol.Size),
					string(vol.VolumeType),
				),
				RiskLevel: "MEDIUM",
			})
		}
	}

	// Old snapshots (>90 days)
	cutoff := time.Now().AddDate(0, 0, -audit.GetThresholds(ctx).SnapshotAgeDays)
	snapPaginator := ec2.NewDescribeSnapshotsPaginator(client, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})
	for snapPaginator.HasMorePages() {
		page, err := snapPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe snapshots: %w", err)
		}
		for _, snap := range page.Snapshots {
			if snap.StartTime != nil && snap.StartTime.Before(cutoff) {
				findings = append(findings, audit.Finding{
					Service:    "ebs_snapshot",
					ResourceID: aws.ToString(snap.SnapshotId),
					Check:      "old_snapshot",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"age=%dd, size=%dGB",
						int(time.Since(*snap.StartTime).Hours()/24),
						aws.ToInt32(snap.VolumeSize),
					),
					RiskLevel: "LOW",
				})
			}
		}
	}

	// GP2 volumes that should be GP3
	gp2Paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{{
			Name:   aws.String("volume-type"),
			Values: []string{"gp2"},
		}},
	})
	for gp2Paginator.HasMorePages() {
		page, err := gp2Paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe gp2 volumes: %w", err)
		}
		for _, vol := range page.Volumes {
			findings = append(findings, audit.Finding{
				Service:    "ebs",
				ResourceID: aws.ToString(vol.VolumeId),
				Check:      "gp2_volume",
				Status:     "WARN",
				Detail: fmt.Sprintf(
					"size=%dGB, GP3 is ~20%% cheaper with better baseline IOPS",
					aws.ToInt32(vol.Size),
				),
				RiskLevel: "LOW",
			})
		}
	}

	return findings, nil
}
