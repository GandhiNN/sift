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

type ebsVolume struct {
	id         string
	size       int32
	volumeType string
	tags       map[string]string
}

type ebsSnapshot struct {
	id        string
	size      int32
	startTime *time.Time
	tags      map[string]string
}

func ec2TagsToMap(tags []ec2types.Tag) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return m
}

func parseEBSVolume(vol ec2types.Volume) ebsVolume {
	return ebsVolume{
		id:         aws.ToString(vol.VolumeId),
		size:       aws.ToInt32(vol.Size),
		volumeType: string(vol.VolumeType),
		tags:       ec2TagsToMap(vol.Tags),
	}
}

func parseEBSSnapshot(snap ec2types.Snapshot) ebsSnapshot {
	return ebsSnapshot{
		id:        aws.ToString(snap.SnapshotId),
		size:      aws.ToInt32(snap.VolumeSize),
		startTime: snap.StartTime,
		tags:      ec2TagsToMap(snap.Tags),
	}
}

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
			v := parseEBSVolume(vol)
			findings = append(findings, audit.Finding{
				Service:    "ebs",
				ResourceID: v.id,
				Tags:       v.tags,
				Check:      "unattached_volume",
				Status:     "WARN",
				Detail: fmt.Sprintf(
					"size=%dGB, type=%s",
					v.size,
					v.volumeType,
				),
				RiskLevel: "MEDIUM",
			})
		}
	}

	// Old snapshots
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
			s := parseEBSSnapshot(snap)
			if s.startTime != nil && s.startTime.Before(cutoff) {
				findings = append(findings, audit.Finding{
					Service:    "ebs_snapshot",
					ResourceID: s.id,
					Tags:       s.tags,
					Check:      "old_snapshot",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"age=%dd, size=%dGB",
						int(time.Since(*s.startTime).Hours()/24),
						s.size,
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
			v := parseEBSVolume(vol)
			findings = append(findings, audit.Finding{
				Service:    "ebs",
				ResourceID: v.id,
				Tags:       v.tags,
				Check:      "gp2_volume",
				Status:     "WARN",
				Detail: fmt.Sprintf(
					"size=%dGB, GP3 is ~20%% cheaper with better baseline IOPS",
					v.size,
				),
				RiskLevel: "LOW",
			})
		}
	}

	return findings, nil
}
