package audit

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
)

// TagCache provides bulk tag lookups via the Resource Groups Tagging API
type TagCache struct {
	mu   sync.Mutex
	tags map[string]map[string]string
}

func NewTagCache(ctx context.Context, cfg aws.Config, arns []string) *TagCache {
	tc := &TagCache{tags: make(map[string]map[string]string)}
	if len(arns) == 0 {
		return tc
	}

	client := resourcegroupstaggingapi.NewFromConfig(cfg)

	for i := 0; i < len(arns); i += 100 {
		end := i + 100
		if end > len(arns) {
			end = len(arns)
		}
		resp, err := client.GetResources(ctx, &resourcegroupstaggingapi.GetResourcesInput{
			ResourceARNList: arns[i:end],
		})
		if err != nil {
			continue
		}
		for _, r := range resp.ResourceTagMappingList {
			arn := aws.ToString(r.ResourceARN)
			m := make(map[string]string, len(r.Tags))
			for _, t := range r.Tags {
				m[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			tc.tags[arn] = m
		}
	}

	return tc
}

func (tc *TagCache) Get(arn string) map[string]string {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.tags[arn]
}
