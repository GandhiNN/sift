package security

import (
	"context"
	"fmt"
	"sync"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
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

func AuditS3(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := s3.NewFromConfig(cfg)

	listResp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	buckets := listResp.Buckets
	results := make([]audit.Finding, len(buckets))
	bar := progress.NewBar(ctx, int64(len(buckets)), "Auditing S3 buckets")

	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for i, b := range buckets {
		if b.Name == nil {
			bar.Add(1)
			continue
		}
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			bucket := parseS3Bucket(ctx, client, name)
			risk := s3Risk(
				bucket.publicBlocked,
				bucket.encrypted,
				bucket.versioning,
				bucket.logging,
			)

			results[i] = audit.Finding{
				Service:    "s3",
				ResourceID: bucket.name,
				Tags:       bucket.tags,
				Check:      "bucket_security",
				Status:     statusFromRisk(risk),
				Detail: fmt.Sprintf(
					"public_blocked=%t, encrypted=%t, versioning=%t, logging=%t",
					bucket.publicBlocked, bucket.encrypted, bucket.versioning, bucket.logging,
				),
				RiskLevel: risk,
			}
			bar.Add(1)
		}(i, *b.Name)
	}

	wg.Wait()

	var filtered []audit.Finding
	for _, f := range results {
		if f.ResourceID != "" {
			filtered = append(filtered, f)
		}
	}
	return filtered, nil
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
