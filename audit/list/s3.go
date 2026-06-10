package list

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func init() {
	Register(Lister{
		Service: "s3",
		Columns: map[string][]Column{
			"bucket": {
				{Key: "size_gb", Header: "SIZE(GB)"},
				{Key: "objects", Header: "OBJECTS"},
				{Key: "versioning", Header: "VERSIONING"},
				{Key: "public_blocked", Header: "PUBLIC BLOCKED"},
				{Key: "lifecycle", Header: "LIFECYCLE"},
				{Key: "created", Header: "CREATED"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, _ string) ([]audit.Resource, error) {
			return ListS3Buckets(ctx, cfg)
		},
	})
}

func ListS3Buckets(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := s3.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	resp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	type bucketInput struct {
		name    string
		created string
	}

	var inputs []bucketInput
	for _, b := range resp.Buckets {
		created := ""
		if b.CreationDate != nil {
			created = b.CreationDate.Format("2006-01-02")
		}
		inputs = append(inputs, bucketInput{name: aws.ToString(b.Name), created: created})
	}
	end := time.Now()
	start := end.AddDate(0, 0, -1)

	resources := audit.FetchAll(ctx, inputs, "Listing S3 buckets",
		func(ctx context.Context, b bucketInput) audit.Resource {
			props := map[string]string{"created": b.created}

			// Bucket size from Cloudwatch
			sizeResp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/S3"),
				MetricName: aws.String("BucketSizeBytes"),
				Dimensions: []cwtypes.Dimension{
					{Name: aws.String("BucketName"), Value: aws.String(b.name)},
					{Name: aws.String("StorageType"), Value: aws.String("StandardStorage")},
				},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
			})
			if err == nil && len(sizeResp.Datapoints) > 0 {
				sizeGB := aws.ToFloat64(sizeResp.Datapoints[0].Average) / (1024 * 1024 * 1024)
				props["size_gb"] = fmt.Sprintf("%.2f", sizeGB)
			}

			// Object count from Cloudwatch
			objResp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/S3"),
				MetricName: aws.String("NumberOfObjects"),
				Dimensions: []cwtypes.Dimension{
					{Name: aws.String("BucketName"), Value: aws.String(b.name)},
					{Name: aws.String("StorageType"), Value: aws.String("AllStorageTypes")},
				},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
			})
			if err == nil && len(objResp.Datapoints) > 0 {
				props["objects"] = strconv.FormatInt(
					int64(aws.ToFloat64(objResp.Datapoints[0].Average)),
					10,
				)
			}

			// Versioning
			ver, err := client.GetBucketVersioning(
				ctx,
				&s3.GetBucketVersioningInput{Bucket: aws.String(b.name)},
			)
			if err == nil {
				props["versioning"] = string(ver.Status)
			}

			// Public access block
			pab, err := client.GetPublicAccessBlock(
				ctx,
				&s3.GetPublicAccessBlockInput{Bucket: aws.String(b.name)},
			)
			if err == nil && pab.PublicAccessBlockConfiguration != nil {
				allBlocked := aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicAcls) &&
					aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicPolicy) &&
					aws.ToBool(pab.PublicAccessBlockConfiguration.IgnorePublicAcls) &&
					aws.ToBool(pab.PublicAccessBlockConfiguration.RestrictPublicBuckets)
				props["public_blocked"] = strconv.FormatBool(allBlocked)
			}
			// Lifecycle
			_, err = client.GetBucketLifecycleConfiguration(
				ctx,
				&s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(b.name)},
			)
			props["lifecycle"] = strconv.FormatBool(err == nil)

			return audit.Resource{
				Service:    "s3",
				ResourceID: b.name,
				Type:       "bucket",
				Properties: props,
			}
		},
	)
	return resources, nil
}
