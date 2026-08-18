package list

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

func init() {
	Register(Lister{
		Service:  "bedrock",
		SubTypes: []string{"models", "provisioned"},
		Columns: map[string][]Column{
			"model": {
				{Key: "invocations_30d", Header: "INVOCATIONS(30d)"},
				{Key: "input_tokens_30d", Header: "INPUT_TOKENS(30d)"},
				{Key: "output_tokens_30d", Header: "OUTPUT_TOKENS(30d)"},
			},
			"provisioned": {
				{Key: "model", Header: "MODEL"},
				{Key: "model_units", Header: "UNITS"},
				{Key: "status", Header: "STATUS"},
				{Key: "commitment", Header: "COMMITMENT"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, subType string) ([]audit.Resource, error) {
			switch subType {
			case "models", "":
				return listBedrockModels(ctx, cfg)
			case "provisioned":
				return listBedrockProvisioned(ctx, cfg)
			default:
				return nil, fmt.Errorf("unknown sub-type %q (use models or provisioned)", subType)
			}
		},
	})
}

// listBedrockModels lists foundation models that have invocation activity in the
// last 30 days, source from CloudWatch metrics (data plane InvokeModel calls are
// not logged by CloudTrail by default). Models with zero activity are omitted.
func listBedrockModels(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := bedrock.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	resp, err := client.ListFoundationModels(ctx, &bedrock.ListFoundationModelsInput{})
	if err != nil {
		return nil, fmt.Errorf("list foundation models: %w", err)
	}

	var resources []audit.Resource
	for _, m := range resp.ModelSummaries {
		modelID := aws.ToString(m.ModelId)
		if modelID == "" {
			continue
		}

		invocations := getBedrockMetric(ctx, cwClient, modelID, "Invocations", cwtypes.StatisticSum)
		// Skip models with no usage in the window.
		if invocations == 0 {
			continue
		}
		inputTokens := getBedrockMetric(
			ctx,
			cwClient,
			modelID,
			"InputTokenCount",
			cwtypes.StatisticSum,
		)
		outputTokens := getBedrockMetric(
			ctx,
			cwClient,
			modelID,
			"OutputTokenCount",
			cwtypes.StatisticSum,
		)

		resources = append(resources, audit.Resource{
			Service:    "bedrock",
			ResourceID: modelID,
			Type:       "model",
			Properties: map[string]string{
				"invocations_30d":   strconv.Itoa(invocations),
				"input_tokens_30d":  strconv.Itoa(inputTokens),
				"output_tokens_30d": strconv.Itoa(outputTokens),
			},
		})
	}
	return resources, nil
}

func listBedrockProvisioned(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := bedrock.NewFromConfig(cfg)

	var resources []audit.Resource
	input := &bedrock.ListProvisionedModelThroughputsInput{}
	for {
		resp, err := client.ListProvisionedModelThroughputs(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list provisioned throughputs: %w", err)
		}
		for _, p := range resp.ProvisionedModelSummaries {
			commitment := string(p.CommitmentDuration)
			if commitment == "" {
				commitment = "none"
			}
			resources = append(resources, audit.Resource{
				Service:    "bedrock",
				ResourceID: aws.ToString(p.ProvisionedModelName),
				Type:       "provisioned",
				Properties: map[string]string{
					"model":       modelIDFromARN(aws.ToString(p.ModelArn)),
					"model_units": strconv.Itoa(int(aws.ToInt32(p.ModelUnits))),
					"status":      string(p.Status),
					"commitment":  commitment,
				},
			})
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	return resources, nil
}

func getBedrockMetric(
	ctx context.Context,
	cwClient *cloudwatch.Client,
	modelID, metric string,
	stat cwtypes.Statistic,
) int {
	end := time.Now()
	start := end.AddDate(0, 0, -30)

	resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/Bedrock"),
		MetricName: aws.String(metric),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("ModelId"), Value: &modelID},
		},
		StartTime:  &start,
		EndTime:    &end,
		Period:     aws.Int32(2592000), // 30 days
		Statistics: []cwtypes.Statistic{stat},
	})
	if err != nil || len(resp.Datapoints) == 0 {
		return 0
	}
	total := 0.0
	for _, dp := range resp.Datapoints {
		total += aws.ToFloat64(dp.Sum)
	}
	return int(total)
}

func modelIDFromARN(arn string) string {
	if idx := strings.LastIndex(arn, "/"); idx != -1 && idx+1 < len(arn) {
		return arn[idx+1:]
	}
	return arn
}
