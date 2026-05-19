package cost

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type s3CostBucket struct {
	name   string
	sizeGB float64
	tags   map[string]string
}

func parseS3CostBucket(
	ctx context.Context,
	client *s3.Client,
	cwClient *cloudwatch.Client,
	name string,
) s3CostBucket {
	b := s3CostBucket{name: name}
	tagResp, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &name})
	if err == nil {
		b.tags = make(map[string]string, len(tagResp.TagSet))
		for _, t := range tagResp.TagSet {
			b.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}

	// Fetch bucket size from Cloudwatch
	end := time.Now()
	start := end.AddDate(0, 0, -2)
	resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/S3"),
		MetricName: aws.String("BucketSizeBytes"),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("BucketName"), Value: &name},
			{Name: aws.String("StorageType"), Value: aws.String("StandardStorage")},
		},
		StartTime:  &start,
		EndTime:    &end,
		Period:     aws.Int32(86400),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	})
	if err == nil && len(resp.Datapoints) > 0 {
		// Use most recent datapoint
		latest := resp.Datapoints[0]
		for _, dp := range resp.Datapoints[1:] {
			if dp.Timestamp.After(*latest.Timestamp) {
				latest = dp
			}
		}
		b.sizeGB = aws.ToFloat64(latest.Average) / (1024 * 1024 * 1024)
	}

	return b
}

func AuditS3Cost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := s3.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	resp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var mu sync.Mutex
	var findings []audit.Finding
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)
	bar := progress.NewBar(ctx, int64(len(resp.Buckets)), "Auditing S3 cost")

	for _, b := range resp.Buckets {
		if b.Name == nil {
			continue
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer bar.Add(1)

			bucket := parseS3CostBucket(ctx, client, cwClient, name)
			monthlyCost := pricing.S3Monthly(bucket.sizeGB)

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
					Detail: fmt.Sprintf(
						"size=%.2fGB, data may grow indefinitely without expiration rules",
						bucket.sizeGB,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"s3",
						"no_lifecycle_policy",
						bucket.name,
						"no lifecycle policy configured",
					),
				})
				mu.Unlock()
			} else {
				mu.Lock()
				findings = append(findings, audit.Finding{
					Service:              "s3",
					ResourceID:           bucket.name,
					Tags:                 bucket.tags,
					Check:                "no_lifecycle_policy",
					Status:               "PASS",
					Detail:               fmt.Sprintf("size=%.2fGB, lifecycle policy configured", bucket.sizeGB),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: monthlyCost,
				})
				mu.Unlock()
			}
		}(*b.Name)
	}

	wg.Wait()
	return findings, nil
}
