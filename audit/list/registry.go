package list

import (
	"context"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type Lister struct {
	Service  string
	SubTypes []string // optional sub-resources (e.g. ["jobs", "crawlers"])
	Fn       func(ctx context.Context, cfg aws.Config, subType string) ([]audit.Resource, error)
}

var listers []Lister

func Register(l Lister) {
	listers = append(listers, l)
}

func Get(service string) *Lister {
	for i := range listers {
		if listers[i].Service == service {
			return &listers[i]
		}
	}
	return nil
}

func Services() []string {
	var s []string
	for _, l := range listers {
		s = append(s, l.Service)
	}
	return s
}

func All() []Lister {
	return listers
}
