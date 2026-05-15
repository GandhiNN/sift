package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/progress"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type ecrSecurityEntry struct {
	name            string
	arn             string
	scanOnPush      bool
	imageTagMutable bool
	tags            map[string]string
}

func parseECRSecurityEntry(
	ctx context.Context,
	client *ecr.Client,
	repo ecrtypes.Repository,
) ecrSecurityEntry {
	e := ecrSecurityEntry{
		name: aws.ToString(repo.RepositoryName),
		arn:  aws.ToString(repo.RepositoryArn),
		scanOnPush: repo.ImageScanningConfiguration != nil &&
			repo.ImageScanningConfiguration.ScanOnPush,
		imageTagMutable: repo.ImageTagMutability == ecrtypes.ImageTagMutabilityMutable,
	}
	tagResp, err := client.ListTagsForResource(
		ctx,
		&ecr.ListTagsForResourceInput{ResourceArn: &e.arn},
	)
	if err == nil {
		e.tags = make(map[string]string, len(tagResp.Tags))
		for _, t := range tagResp.Tags {
			e.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}
	return e
}

func ecrRisk(scanOnPush, imageTagMutable bool) string {
	switch {
	case !scanOnPush && imageTagMutable:
		return "HIGH"
	case !scanOnPush:
		return "MEDIUM"
	case imageTagMutable:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

func AuditECR(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := ecr.NewFromConfig(cfg)

	var allRepos []ecrtypes.Repository
	paginator := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe repositories: %w", err)
		}
		allRepos = append(allRepos, page.Repositories...)
	}

	results := make([]audit.Finding, len(allRepos))
	bar := progress.NewBar(ctx, int64(len(allRepos)), "Auditing ECR security")

	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for i, repo := range allRepos {
		wg.Add(1)
		go func(i int, repo ecrtypes.Repository) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			e := parseECRSecurityEntry(ctx, client, repo)
			risk := ecrRisk(e.scanOnPush, e.imageTagMutable)

			detail := fmt.Sprintf(
				"scan_on_push=%t, image_tag_mutable=%t",
				e.scanOnPush,
				e.imageTagMutable,
			)

			results[i] = audit.Finding{
				Service:    "ecr",
				ResourceID: e.name,
				Tags:       e.tags,
				Check:      "ecr_security",
				Status:     statusFromRisk(risk),
				Detail:     detail,
				RiskLevel:  risk,
			}
			bar.Add(1)
		}(i, repo)
	}
	wg.Wait()

	return results, nil
}
