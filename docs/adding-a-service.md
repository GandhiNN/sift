# Adding a New Service

This guide explains how to add a new audit service to sift.

## Architecture

```
audit/registry.go   — Self-registration of checkers per module (security, cost, ops)
audit/runner.go     — Generic parallel orchestrator (RunChecks)
audit/process.go    — Concurrent item processor (ProcessAll, ProcessAllMulti, FetchAll)
```

Each module (`security`, `cost`, `ops`) has a registry. Services register themselves via `init()`, so adding a new service requires **one file with zero edits elsewhere**.

### Package layout

```
audit/
├── runner.go          # RunChecks — generic orchestrator
├── registry.go        # Register/CheckersFor/ValidServices
├── process.go         # ProcessAll, ProcessAllMulti, FetchAll
├── finding.go         # Finding struct
├── security/          # Security audit checkers
├── cost/              # Cost audit checkers
├── ops/               # Ops audit checkers
└── triage/            # Triage investigation (own package, consumes security helpers)
```

## Adding a Security Check

Create `audit/security/<service>.go`:

```go
package security

import (
    "context"
    "fmt"
    "sift/audit"
    "sift/audit/remediation"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/sqs"
)

func init() {
    audit.Register(Module, audit.Checker{Name: "sqs", Fn: AuditSQS})
}

func AuditSQS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
    client := sqs.NewFromConfig(cfg)

    // 1. Paginate to collect resources
    var queues []string
    // ... pagination logic ...

    // 2. Process each item concurrently (single finding per item)
    return audit.ProcessAll(ctx, queues, "Auditing SQS security", func(ctx context.Context, url string) audit.Finding {
        // Business logic only — concurrency, progress bars handled automatically
        risk := "MINIMAL"
        detail := fmt.Sprintf("queue=%s", url)

        var rem *audit.Remediation
        if risk != "MINIMAL" {
            rem = remediation.Recommend("security", "sqs", "sqs_check", url, detail)
        }

        return audit.Finding{
            Service:     "sqs",
            ResourceID:  url,
            Check:       "sqs_check",
            Status:      statusFromRisk(risk),
            Detail:      detail,
            RiskLevel:   risk,
            Remediation: rem,
        }
    }), nil
}
```

That's it. The service automatically appears in `sift security --service sqs`.

## Adding a Cost Check

Same pattern in `audit/cost/<service>.go`:

```go
package cost

import (
    "context"
    "sift/audit"

    "github.com/aws/aws-sdk-go-v2/aws"
)

func init() {
    audit.Register(Module, audit.Checker{Name: "sqs", Fn: AuditSQSCost})
}

func AuditSQSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
    // ... fetch resources ...

    return audit.ProcessAll(ctx, items, "Auditing SQS cost", func(ctx context.Context, item Item) audit.Finding {
        // cost analysis logic
    }), nil
}
```

## Processing Helpers

| Helper | Returns | Use when |
|--------|---------|----------|
| `audit.ProcessAll[T]` | `[]Finding` | Each item produces exactly **one** finding |
| `audit.ProcessAllMulti[T]` | `[]Finding` | Each item may produce **multiple** findings |
| `audit.FetchAll[T, R]` | `[]R` | You need to fetch domain objects (not findings) in parallel |

All three handle concurrency (semaphore), progress bars, and respect `--concurrency` and `--quiet` flags automatically.

### Domain objects vs Findings

**Findings** (`audit.Finding`) are the output format shown to users — fixed structure with service, resource ID, risk level, status, detail, remediation.

**Domain objects** are intermediate structs with raw AWS data, fetched before you can assess risk.

Use `FetchAll` → domain objects when you have a multi-phase pipeline:

```
1. Fetch      — describe N resources in parallel → domain objects (FetchAll)
2. Enrich     — batch-fetch shared data (SGs, route tables) using info from step 1
3. Assess     — compute risk per item using enriched context → findings (ProcessAll)
```

If everything can be done in one pass (no shared lookups), skip domain objects and use `ProcessAll` directly.

### FetchAll example

Use `FetchAll` when you need to describe resources in parallel before processing them (e.g., batch-fetching data that feeds into a later assessment phase):

```go
notebooks := audit.FetchAll(ctx, names, "Describing notebooks", func(ctx context.Context, name string) Notebook {
    desc, err := client.Describe(ctx, &DescribeInput{Name: &name})
    if err != nil {
        return Notebook{} // filter out later
    }
    return Notebook{Name: name, Status: desc.Status}
})
```

## Adding an Ops Check

Register in `audit/ops/`:

```go
func init() {
    audit.Register(ops.Module, audit.Checker{Name: "myservice", Fn: AuditMyServiceOps})
}
```

The `--check` flag for sub-check filtering is passed via context (`audit.GetChecks(ctx)`).

## When Helpers Don't Fit

Some services have multi-phase logic that doesn't map to "process each item independently":

- **Pre-computed lookup maps** (e.g., DMS task counts per instance) — compute the map first, then pass it into `ProcessAllMulti` via closure capture.
- **Simple fan-out** (e.g., baseline runs CloudTrail + GuardDuty in parallel) — use a plain `sync.WaitGroup` with 2 goroutines.
- **Nested parallelism** (e.g., EKS clusters → nodegroups) — use `ProcessAllMulti` at the outer level and sequential loops inside.

## Checklist

1. Create one file in the appropriate `audit/<module>/` directory
2. Add `func init()` with `audit.Register()`
3. Implement the `func(context.Context, aws.Config) ([]audit.Finding, error)` signature
4. Use `ProcessAll`, `ProcessAllMulti`, or `FetchAll` for the processing loop
5. Add remediation via `remediation.Recommend()` for non-MINIMAL findings
6. Build and test: `go build ./... && go test ./...`

No changes needed in `cmd/`, no service maps to update, no orchestrator edits.
