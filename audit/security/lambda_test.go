package security

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

type mockLambdaClient struct {
	tags      map[string]string
	urlConfig *lambda.GetFunctionUrlConfigOutput
	urlErr    error
}

func (m *mockLambdaClient) ListTags(
	_ context.Context,
	_ *lambda.ListTagsInput,
	_ ...func(*lambda.Options),
) (*lambda.ListTagsOutput, error) {
	return &lambda.ListTagsOutput{Tags: m.tags}, nil
}

func (m *mockLambdaClient) GetFunctionUrlConfig(
	_ context.Context,
	_ *lambda.GetFunctionUrlConfigInput,
	_ ...func(*lambda.Options),
) (*lambda.GetFunctionUrlConfigOutput, error) {
	if m.urlErr != nil {
		return nil, m.urlErr
	}
	return m.urlConfig, nil
}

func TestParseLambdaFunction(t *testing.T) {
	mock := &mockLambdaClient{tags: map[string]string{"team": "platform"}}

	fn := lambdatypes.FunctionConfiguration{
		FunctionName: aws.String("my-func"),
		FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123:function:my-func"),
		Runtime:      lambdatypes.RuntimePython312,
	}

	f := parseLambdaFunction(context.Background(), mock, fn)

	if f.name != "my-func" {
		t.Errorf("name = %s, want my-func", f.name)
	}
	if f.runtime != string(lambdatypes.RuntimePython312) {
		t.Errorf("runtime = %s, want python3.12", f.runtime)
	}
	if f.tags["team"] != "platform" {
		t.Errorf("tags[team] = %s, want platform", f.tags["team"])
	}
}

func TestLambdaRiskDeprecatedRuntime(t *testing.T) {
	if risk := lambdaRisk(false, "", true); risk != "HIGH" {
		t.Errorf("risk = %s, want HIGH", risk)
	}
}

func TestLambdaRiskPublicURLNoAuth(t *testing.T) {
	if risk := lambdaRisk(true, "NONE", false); risk != "CRITICAL" {
		t.Errorf("risk = %s, want CRITICAL", risk)
	}
}

func TestLambdaRiskPublicURLWithAuth(t *testing.T) {
	if risk := lambdaRisk(true, "AWS_IAM", false); risk != "MEDIUM" {
		t.Errorf("risk = %s, want MEDIUM", risk)
	}
}

func TestLambdaRiskClean(t *testing.T) {
	if risk := lambdaRisk(false, "", false); risk != "MINIMAL" {
		t.Errorf("risk = %s, want MINIMAL", risk)
	}
}
