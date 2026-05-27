package security

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type mockECRClient struct {
	tags map[string]string
}

func (m *mockECRClient) ListTagsForResource(
	_ context.Context,
	_ *ecr.ListTagsForResourceInput,
	_ ...func(*ecr.Options),
) (*ecr.ListTagsForResourceOutput, error) {
	var tags []ecrtypes.Tag
	for k, v := range m.tags {
		tags = append(tags, ecrtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return &ecr.ListTagsForResourceOutput{Tags: tags}, nil
}

func TestParseECRSecurityEntry(t *testing.T) {
	mock := &mockECRClient{tags: map[string]string{"env": "prod"}}

	repo := ecrtypes.Repository{
		RepositoryName:             aws.String("my-repo"),
		RepositoryArn:              aws.String("arn:aws:ecr:us-east-1:123:repository/my-repo"),
		ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: true},
		ImageTagMutability:         ecrtypes.ImageTagMutabilityImmutable,
	}

	e := parseECRSecurityEntry(context.Background(), mock, repo)

	if e.name != "my-repo" {
		t.Errorf("name = %s, want my-repo", e.name)
	}
	if !e.scanOnPush {
		t.Error("expected scanOnPush=true")
	}
	if e.imageTagMutable {
		t.Error("expected imageTagMutable=false")
	}
	if e.tags["env"] != "prod" {
		t.Errorf("tags[env] = %s, want prod", e.tags["env"])
	}
	if risk := ecrRisk(e.scanOnPush, e.imageTagMutable); risk != "MINIMAL" {
		t.Errorf("risk = %s, want MINIMAL", risk)
	}
}

func TestECRRiskNoScanMutable(t *testing.T) {
	mock := &mockECRClient{}

	repo := ecrtypes.Repository{
		RepositoryName:             aws.String("bad-repo"),
		RepositoryArn:              aws.String("arn:aws:ecr:us-east-1:123:repository/bad-repo"),
		ImageScanningConfiguration: nil,
		ImageTagMutability:         ecrtypes.ImageTagMutabilityMutable,
	}

	e := parseECRSecurityEntry(context.Background(), mock, repo)

	if risk := ecrRisk(e.scanOnPush, e.imageTagMutable); risk != "HIGH" {
		t.Errorf("risk = %s, want HIGH", risk)
	}
}
