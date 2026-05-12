package cost

import (
	"context"
	"fmt"
	"sync"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type s3CostBucket struct {
	name string
	tags map[string]string
}

func parseS3CostBucket(ctx context.Context, client *s3.Client, name string) s3CostBucket {
	b := s3CostBucket{name: name}
	tagResp, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &name})
	if err == nil {
		b.tags = make(map[string]string, len(tagResp.TagSet))
		for _, t := range tagResp.TagSet {
			b.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}
	return b
}

func AuditS3Cost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := s3.NewFromConfig(cfg)

	resp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var mu sync.Mutex
	var findings []audit.Finding
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for _, b := range resp.Buckets {
		if b.Name == nil {
			continue
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			bucket := parseS3CostBucket(ctx, client, name)

			_, err := client.GetBucketLifecycleConfiguration(
				ctx,
				&s3.GetBucketLifecycleConfigurationInput{Bucket: &name},
			)
			if err != nil {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:    "s3",
					ResourceID: bucket.name,
					Tags:       bucket.tags,
					Check:      "no_lifecycle_policy",
					Status:     "WARN",
					Detail:     "data may grow indefinitely without expiration rules",
					RiskLevel:  "MEDIUM",
				})
				mu.Unlock()
			}
		}(*b.Name)
	}

	wg.Wait()
	return findings, nil
}
