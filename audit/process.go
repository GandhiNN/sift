package audit

import (
	"context"
	"sync"

	"sift/audit/progress"
)

// ProcessAll runs fn concurrently for each item, respecting concurrency limits and showing a progress bar.
func ProcessAll[T any](
	ctx context.Context,
	items []T,
	label string,
	fn func(context.Context, T) Finding,
) []Finding {
	results := make([]Finding, len(items))
	bar := progress.NewBar(ctx, int64(len(items)), label)

	var wg sync.WaitGroup
	sem := make(chan struct{}, GetThresholds(ctx).Concurrency)

	for i, item := range items {
		wg.Add(1)
		go func(i int, item T) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = fn(ctx, item)
			bar.Add(1)
		}(i, item)
	}
	wg.Wait()
	return results
}

// ProcessAllMulti runs fn concurrently for each item where fn can return multiple findings per item.
func ProcessAllMulti[T any](
	ctx context.Context,
	items []T,
	label string,
	fn func(context.Context, T) []Finding,
) []Finding {
	results := make([][]Finding, len(items))
	bar := progress.NewBar(ctx, int64(len(items)), label)

	var wg sync.WaitGroup
	sem := make(chan struct{}, GetThresholds(ctx).Concurrency)

	for i, item := range items {
		wg.Add(1)
		go func(i int, item T) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = fn(ctx, item)
			bar.Add(1)
		}(i, item)
	}
	wg.Wait()

	var out []Finding
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}
