package list

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func init() {
	Register(Lister{
		Service: "s3",
		Fn: func(ctx context.Context, cfg aws.Config, _ string) ([]audit.Resource, error) {
			return ListS3Buckets(ctx, cfg)
		},
	})
}

func ListS3Buckets(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := s3.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	spinner := progress.NewSpinner(ctx, "Listing S3 buckets")

	resp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		spinner.Finish()
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	end := time.Now()
	start := end.AddDate(0, 0, -1)

	var resources []audit.Resource
	for _, b := range resp.Buckets {
		name := aws.ToString(b.Name)
		props := map[string]string{}

		if b.CreationDate != nil {
			props["created"] = b.CreationDate.Format("2006-01-02")
		}

		// Bucket size from CloudWatch
		sizeResp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
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
		if err == nil && len(sizeResp.Datapoints) > 0 {
			sizeGB := aws.ToFloat64(sizeResp.Datapoints[0].Average) / (1024 * 1024 * 1024)
			props["size_gb"] = fmt.Sprintf("%.2f", sizeGB)
		}

		// Object count from CloudWatch
		objResp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
			Namespace:  aws.String("AWS/S3"),
			MetricName: aws.String("NumberOfObjects"),
			Dimensions: []cwtypes.Dimension{
				{Name: aws.String("BucketName"), Value: &name},
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
		ver, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &name})
		if err == nil {
			props["versioning"] = string(ver.Status)
		}

		// Public access block
		pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &name})
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
			&s3.GetBucketLifecycleConfigurationInput{Bucket: &name},
		)
		props["lifecycle"] = strconv.FormatBool(err == nil)

		resources = append(resources, audit.Resource{
			Service:    "s3",
			ResourceID: name,
			Type:       "bucket",
			Properties: props,
		})
		spinner.Add(1)
	}
	spinner.Finish()
	return resources, nil
}
