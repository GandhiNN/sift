package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type s3Bucket struct {
	name          string
	publicBlocked bool
	encrypted     bool
	versioning    bool
	logging       bool
	tags          map[string]string
}

func parseS3Bucket(ctx context.Context, client *s3.Client, name string) s3Bucket {
	b := s3Bucket{name: name}

	pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &name})
	if err == nil && pab.PublicAccessBlockConfiguration != nil {
		c := pab.PublicAccessBlockConfiguration
		b.publicBlocked = aws.ToBool(c.BlockPublicAcls) &&
			aws.ToBool(c.BlockPublicPolicy) &&
			aws.ToBool(c.IgnorePublicAcls) &&
			aws.ToBool(c.RestrictPublicBuckets)
	}

	enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &name})
	if err == nil && enc.ServerSideEncryptionConfiguration != nil {
		b.encrypted = len(enc.ServerSideEncryptionConfiguration.Rules) > 0
	}

	ver, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &name})
	if err == nil {
		b.versioning = ver.Status == types.BucketVersioningStatusEnabled
	}

	log, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: &name})
	if err == nil {
		b.logging = log.LoggingEnabled != nil
	}

	tagResp, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &name})
	if err == nil {
		b.tags = make(map[string]string, len(tagResp.TagSet))
		for _, t := range tagResp.TagSet {
			b.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}

	return b
}

func hasS3DataEvents(ctx context.Context, cfg aws.Config) bool {
	ctClient := cloudtrail.NewFromConfig(cfg)
	resp, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return false
	}
	for _, trail := range resp.TrailList {
		selResp, err := ctClient.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
			TrailName: trail.TrailARN,
		})
		if err != nil {
			continue
		}
		for _, sel := range selResp.EventSelectors {
			for _, dr := range sel.DataResources {
				if aws.ToString(dr.Type) == "AWS::S3::Object" {
					return true
				}
			}
		}
		for _, adv := range selResp.AdvancedEventSelectors {
			for _, fs := range adv.FieldSelectors {
				if aws.ToString(fs.Field) == "resources.type" {
					for _, v := range fs.Equals {
						if v == "AWS::S3::Object" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func AuditS3(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := s3.NewFromConfig(cfg)

	listResp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var names []string
	for _, b := range listResp.Buckets {
		if b.Name != nil {
			names = append(names, *b.Name)
		}
	}
	dataEventsEnabled := hasS3DataEvents(ctx, cfg)

	return audit.ProcessAll(
		ctx,
		names,
		"Auditing S3 buckets",
		func(ctx context.Context, name string) audit.Finding {
			bucket := parseS3Bucket(ctx, client, name)
			risk := s3Risk(
				bucket.publicBlocked,
				bucket.encrypted,
				bucket.versioning,
				bucket.logging,
			)

			detail := fmt.Sprintf(
				"public_blocked=%t, encrypted=%t, versioning=%t, logging=%t, cloudtrail_data_events=%t",
				bucket.publicBlocked,
				bucket.encrypted,
				bucket.versioning,
				bucket.logging,
				dataEventsEnabled,
			)
			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend(
					"security",
					"s3",
					"bucket_security",
					bucket.name,
					detail,
				)
			}

			return audit.Finding{
				Service:     "s3",
				ResourceID:  bucket.name,
				Tags:        bucket.tags,
				Check:       "bucket_security",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
		},
	), nil
}

func s3Risk(publicBlocked, encrypted, versioning, logging bool) string {
	switch {
	case !publicBlocked && !encrypted:
		return "CRITICAL"
	case !publicBlocked:
		return "HIGH"
	case !encrypted:
		return "MEDIUM"
	case !versioning || !logging:
		return "LOW"
	default:
		return "MINIMAL"
	}
}
