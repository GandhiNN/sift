package list

import (
	"context"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type ListFunc func(context.Context, aws.Config) ([]audit.Resource, error)

var Registry = map[string]ListFunc{
	"glue/jobs":     ListGlueJobs,
	"glue/crawlers": ListGlueCrawlers,
}
