# Concurrency Patterns

This project uses a consistent set of Go concurrency patterns to parallelize AWS API calls safely.

## Semaphore-bounded fan-out

Every audit function that processes a list of resources concurrently follows the same shape:

```go
var mu sync.Mutex
var findings []audit.Finding
var wg sync.WaitGroup
sem := make(chan struct{}, 10) // buffered channel = semaphore

for _, item := range items {
    wg.Add(1)
    go func(item Item) {
        defer wg.Done()
        sem <- struct{}{} // acquire slot (blocks if 10 goroutines are already running)
        defer func() { <-sem }() // release slot when done

        result := process(item)

        mu.Lock()
        findings = append(findings, results)
        mu.Unlock()
    }(item)
}
wg.Wait()
```

**Why each piece exists:**

- `sync.WaitGroup` - the caller blocks on `wg.Wait()` until every goroutine finishes. Without it, the function would return before goroutines complete.
- `sem` (buffered channel) - limits how many goroutines run concurrently. We launch one goroutine per resource, but only 10 execute at a time. This prevents flooding the AWS API with hundreds of simultaneous requests, which would cause throttling. The buffer size (10) is the concurrency limit - writing to a full channel blocks until another goroutine reads from it.
- `sync.Mutex` - protects the shared `findings` slice. Go slices are not safe for concurrent writes. Without the mutex, two goroutines appending simultaneously would corrupt the slice (data race). The mutex ensures only one goroutine appends at a time.

## Pre-allocated results (index-based)

Some functions use a variation that avoids the mutex entirely:

```go
results := make([]audit.Finding, len(items)) // pre-allocate with known size

for i, item := range items {
    wg.Add(1)
    go func(i int, item Item) {
        defer wg.Done()
        sem <- struct{}{}
        defer func() { <-sem }()

        results[i] = process(item) // each goroutine writes to its won index
    }(i, item)
}
wg.Wait()
```

Since each goroutine writes to a distinct index (`results[i]`), there's no concurrent write to the same memory - no mutex needed. Used in `security.s3.go`, `security/rds.go`, and `security/triage.go`,

**Trade-Off:** The result slice may contain zero-value entries if a goroutine fails silently (returns early without writing). These are filtered out after `wg.Wait()`.

## Orchestrator-level parallelism

The top-level orchestrators (`security/security.go`, `cost/cost.go`) run each service check as a concurrent goroutine:

```go
results := make([][]audit.Finding, len(checks))

var wg sync.WaitGroup
for i, c := range checks {
    wg.Add(1)
    go func(i int, name string, fn CheckFunc) {
        defer wg.Done()
        findings, err := fn(ctx, cfg)
        if err != nil {
            slog.Warn("check failed", "service", name, "error", err)
        } else {
            results[i] = findings
        }
    }(i, c.name, c.fn)
}
wg.Wait()
```

No semaphore here - each service check already limits its own internal concurrency. No mutex either - each goroutine writes to its own index in `results`.

## Multi-region parallelism

The CLI commands (`cmd/security.go`, `cmd/cost.go`, `cmd/triage.go`) run the same audit across multiple AWS regions concurrently:

```go
var mu sync.Mutex
var allResults []audit.Finding
var wg sync.WaitGroup

for _, cfg := range configs { // one config per region
    wg.Add(1)
    go func(cfg aws.Config) {
        defer wg.Done()
        results, _ := audit(ctx, cfg, services)
        mu.Lock()
        allResults = append(allResults, results...)
        mu.Unlock()
    }(cfg)
}
wg.Wait()
```

This is the outermost layer. Each region spawns its own orchestrator, which spawns service checks, which spawn per-resource goroutines -> three levels of concurrency, each bounded at its own level.

## Common mistakes to watch for

1. **Forgetting `mu.Lock()` before append** - causes data races. Go's race detector (`go test -race`) catches this.
2. **Capturing loop variables** - always pass loop variables as function arguments (`go func(item Item) {...}(item)`), not by closure. Closures over loop variable see the final value after the loop ends.
3. **Unlocking without locking** - calling `mu.Unlock()` without `mu.Lock()` panics at runtime.
4. **Ignoring context cancellation** - goroutines should check `ctx.Done()` or pass `ctx` to AWS SDK calls so they stop promptly on Ctrl+C