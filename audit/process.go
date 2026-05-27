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

// FetchAll runs fn concurrently for each item and returns results of any type.
// Use this when you need to fetch domain objects (not findings) in parallel.
func FetchAll[T any, R any](
	ctx context.Context,
	items []T,
	label string,
	fn func(context.Context, T) R,
) []R {
	results := make([]R, len(items))
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
