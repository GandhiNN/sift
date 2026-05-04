package cost

import (
	"context"
	"fmt"
	"sync"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func AuditECRCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
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

	var mu sync.Mutex
	var findings []audit.Finding
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, repo := range allRepos {
		name := aws.ToString(repo.RepositoryName)

		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check for missing lifecycle policy
			_, err := client.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{
				RepositoryName: &name,
			})
			if err != nil {
				// Count images to show impact
				imgResp, _ := client.DescribeImages(ctx, &ecr.DescribeImagesInput{
					RepositoryName: &name,
				})
				imgCount := 0
				if imgResp != nil {
					imgCount = len(imgResp.ImageDetails)
				}
				mu.Lock()

				findings = append(findings, audit.Finding{
					Service:    "ecr",
					ResourceID: name,
					Check:      "no_lifecycle_policy",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"images=%d, old images never cleaned up ($0.10/GB/mo)",
						imgCount,
					),
					RiskLevel: "LOW",
				})
				mu.Unlock()
			}
		}(name)
	}
	wg.Wait()
	return findings, nil
}
