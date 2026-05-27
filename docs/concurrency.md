# Concurrency Patterns

This project uses generic helpers and consistent Go concurrency patterns to parallelize AWS API calls safely.

## ProcessAll / ProcessAllMulti / FetchAll (preferred)

Most services use the generic helpers in `audit/process.go`. These encapsulate the semaphore, WaitGroup, and progress bar:

```go
// Single finding per item
results := audit.ProcessAll(ctx, items, "Auditing X", func(ctx context.Context, item Item) audit.Finding {
    return process(item)
})

// Multiple findings per item
results := audit.ProcessAllMulti(ctx, items, "Auditing X", func(ctx context.Context, item Item) []audit.Finding {
    return processMulti(item)
})

// Fetch domain objects (not findings) in parallel
objects := audit.FetchAll(ctx, names, "Describing X", func(ctx context.Context, name string) MyStruct {
    return describe(name)
})
```

**What they handle for you:**
- Semaphore-bounded concurrency (respects `--concurrency` flag)
- Progress bar (respects `--quiet` flag)
- Pre-allocated result slice (no mutex needed)
- WaitGroup lifecycle

**When to use which:**

| Helper | Returns | Use case |
|--------|---------|----------|
| `ProcessAll[T]` | `[]Finding` | One finding per item |
| `ProcessAllMulti[T]` | `[]Finding` | Zero or more findings per item |
| `FetchAll[T, R]` | `[]R` | Fetch domain objects for a later assessment phase |

## Manual concurrency (when helpers don't fit)

Two cases still use manual patterns:

### Simple fan-out (2-3 independent tasks)

Used in `security/baseline.go` — runs CloudTrail and GuardDuty checks in parallel:

```go
var wg sync.WaitGroup
wg.Add(2)
go func() { defer wg.Done(); ctFindings, ctErr = auditCloudTrail(ctx, cfg) }()
go func() { defer wg.Done(); gdFindings, gdErr = auditGuardDuty(ctx, cfg) }()
wg.Wait()
```

No semaphore needed — only 2 goroutines.

### Multi-phase with pre-computed maps

Used when processing depends on batch-fetched shared data (e.g., `cost/ec2.go`):

```go
// Phase 1: Fetch all items (sequential pagination)
running := paginate(...)

// Phase 2: Pre-compute shared data
// (e.g., previous-gen check — pure CPU, no parallelism needed)

// Phase 3: Parallel API calls using ProcessAllMulti
cpuFindings := audit.ProcessAllMulti(ctx, running, "Checking CPU", func(ctx context.Context, i Instance) []audit.Finding {
    // CloudWatch API call per instance
})
```

## Orchestrator-level parallelism

The `audit.RunChecks` function (in `audit/runner.go`) runs each service check as a concurrent goroutine:

```go
// Simplified from runner.go
results := make([][]Finding, len(checks))
var wg sync.WaitGroup
for i, c := range checks {
    wg.Add(1)
    go func(i int, name string, fn CheckFn) {
        defer wg.Done()
        results[i], _ = fn(ctx, cfg)
    }(i, c.Name, c.Fn)
}
wg.Wait()
```

No semaphore — each service check limits its own internal concurrency. No mutex — each goroutine writes to its own index.

## Multi-region parallelism

The CLI runner (`cmd/run.go`) runs the same audit across multiple AWS regions concurrently:

```go
var mu sync.Mutex
var allFindings []audit.Finding
var wg sync.WaitGroup
for _, cfg := range configs {
    wg.Add(1)
    go func(cfg aws.Config) {
        defer wg.Done()
        findings, _ := fn(ctx, cfg, services)
        mu.Lock()
        allFindings = append(allFindings, findings...)
        mu.Unlock()
    }(cfg)
}
wg.Wait()
```

Three levels of concurrency, each bounded at its own level:
- Region level: one goroutine per region (unbounded — typically 1-20 regions)
- Service level: one goroutine per service within `RunChecks` (unbounded — ~18 services)
- Item level: bounded by `--concurrency` flag (default 10) via `ProcessAll`/`ProcessAllMulti`

## Common mistakes to watch for

1. **Forgetting `mu.Lock()` before append** — causes data races. Use `go test -race` to catch.
2. **Capturing loop variables** — always pass as function arguments. The generic helpers handle this for you.
3. **Ignoring context cancellation** — pass `ctx` to AWS SDK calls so they stop on Ctrl+C.
4. **Using manual patterns when helpers work** — prefer `ProcessAll`/`ProcessAllMulti`/`FetchAll`. Only use manual concurrency for fan-out or multi-phase pipelines.
