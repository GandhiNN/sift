# Adding a New Service

This guide explains how to add a new audit service to sift.

## Architecture

```
audit/registry.go   — Self-registration of checkers per module (security, cost, ops)
audit/runner.go     — Generic parallel orchestrator (RunChecks)
audit/process.go    — Concurrent item processor (ProcessAll, ProcessAllMulti)
```

Each module (`security`, `cost`, `ops`) has a registry. Services register themselves via `init()`, so adding a new service requires **one file with zero edits elsewhere**.

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

## ProcessAll vs ProcessAllMulti

| Helper | Use when |
|--------|----------|
| `audit.ProcessAll[T]` | Each item produces exactly **one** finding |
| `audit.ProcessAllMulti[T]` | Each item may produce **multiple** findings |

Both handle concurrency (semaphore), progress bars, and respect `--concurrency` and `--quiet` flags automatically.

## When ProcessAll Doesn't Fit

Some services have complex multi-phase logic (e.g., pre-computing lookup maps, mixed sequential/parallel). In those cases, use the standard goroutine pattern directly. See `audit/cost/dms.go` or `audit/security/elb.go` for examples.

## Adding an Ops Check

Register in `audit/ops/`:

```go
func init() {
    audit.Register(ops.Module, audit.Checker{Name: "myservice", Fn: AuditMyServiceOps})
}
```

The `--check` flag for sub-check filtering is passed via context (`audit.GetChecks(ctx)`).

## Checklist

1. Create one file in the appropriate `audit/<module>/` directory
2. Add `func init()` with `audit.Register()`
3. Implement the `func(context.Context, aws.Config) ([]audit.Finding, error)` signature
4. Use `ProcessAll` or `ProcessAllMulti` for the processing loop
5. Add remediation via `remediation.Recommend()` for non-MINIMAL findings
6. Build and test: `go build ./... && go test ./...`

No changes needed in `cmd/`, no service maps to update, no orchestrator edits.
