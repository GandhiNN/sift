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

			results[i] = auditBucket(ctx, client, name)
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

func auditBucket(ctx context.Context, client *s3.Client, name string) audit.Finding {
	publicBlocked := false
	encrypted := false
	versioning := false
	logging := false

	pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: &name,
	})
	if err == nil && pab.PublicAccessBlockConfiguration != nil {
		c := pab.PublicAccessBlockConfiguration
		publicBlocked = aws.ToBool(c.BlockPublicAcls) &&
			aws.ToBool(c.BlockPublicPolicy) &&
			aws.ToBool(c.IgnorePublicAcls) &&
			aws.ToBool(c.RestrictPublicBuckets)
	}

	enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: &name,
	})
	if err == nil && enc.ServerSideEncryptionConfiguration != nil {
		encrypted = len(enc.ServerSideEncryptionConfiguration.Rules) > 0
	}

	ver, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: &name,
	})
	if err == nil {
		versioning = ver.Status == types.BucketVersioningStatusEnabled
	}

	log, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
		Bucket: &name,
	})
	if err == nil {
		logging = log.LoggingEnabled != nil
	}

	risk := s3Risk(publicBlocked, encrypted, versioning, logging)

	return audit.Finding{
		Service:    "s3",
		ResourceID: name,
		Check:      "bucket_security",
		Status:     statusFromRisk(risk),
		Detail: fmt.Sprintf(
			"public_blocked=%t, encrypted=%t, versioning=%t, logging=%t",
			publicBlocked,
			encrypted,
			versioning,
			logging,
		),
		RiskLevel: risk,
	}
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
