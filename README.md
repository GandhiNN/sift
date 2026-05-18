# sift

![sift](assets/sift.png)

AWS security and cost audit CLI tool. Scans your AWS resources for misconfigurations, overly permissive policies, unused resources, and network exposure risks. Includes estimated cost per resource and scan history with delta reporting.

## Install

```bash
make build
```

Requires Go 1.25+ and a configured AWS profile (supports SSO, static credentials, and all standard AWS credential sources).

## Usage

```bash
sift <command> --profile <aws-profile> [flags]
```

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | `default` | AWS profile name (from `~/.aws/config`) |
| `--format` | `table` (terminal) / `json` (pipe) | Output format: `json`, `csv`, or `table` |
| `--risk-level` | | Minimum risk level to show: `MINIMAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--region` | profile region | AWS region(s), comma-separated or `all` |
| `--sort-by` | `risk` | Sort results by: `risk` or `cost` |
| `--diff` | `false` | Compare results to previous scan |
| `--no-save` | `false` | Don't save scan results to history |
| `--verbose` | `false` | Show detailed log output |
| `--output`, `-o` | stdout | Write results to file instead of stdout |

### Commands

#### Security

Audit AWS resource security posture across services.

```bash
# All services
sift security --profile icloud-dev

# Specific services
sift security --profile icloud-dev --service ec2,s3
sift security --profile icloud-dev --service eks

# Only high and critical findings
sift security --profile icloud-dev --risk-level HIGH
```

Available services: `ec2`, `sagemaker`, `s3`, `rds`, `eks`, `iam`, `secrets`, `glue`, `lambda`, `dynamodb`, `elb`, `dms`, `ecr`

#### Cost

Detect cost waste across AWS resources. Shows estimated monthly cost per resource.

```bash
# All services
sift cost --profile icloud-dev

# Specific services
sift cost --profile icloud-dev --service ec2,s3
sift cost --profile icloud-dev --service ebs,cloudwatch

# Sort by highest cost first
sift cost --profile icloud-dev --sort-by cost

# Show what changed since last scan
sift cost --profile icloud-dev --diff
```

Available services: `ec2`, `ebs`, `rds`, `s3`, `eks`, `network`, `cloudwatch`, `ecr`, `secrets`, `glue`, `lambda`, `dynamodb`, `dms`, `elb`, `sagemaker`

#### Ops

Audit operational risks and service limits.

```bash
# All services
sift ops --profile icloud-dev

# Specific services
sift ops --profile icloud-dev --service glue
```

Available services: `glue`

#### Triage

Deep investigation of EC2 instances — combines security posture, IAM role analysis, VPC flow log queries, and baseline checks (CloudTrail/GuardDuty) to detect outbound connections to public IPs.

```bash
# All instances
sift triage --profile icloud-dev --log-group /vpc/flowlogs

# Single instance
sift triage --profile icloud-dev --log-group /vpc/flowlogs --instance i-0abc123
```

| Flag | Required | Description |
|------|----------|-------------|
| `--log-group` | Yes | CloudWatch log group for VPC flow logs |
| `--instance` | No | Target a specific EC2 instance ID |

## Estimated cost

Cost findings include an `estimated_monthly_cost` field calculated from a static pricing table (eu-west-1). The table output shows a `$/MO` column and the summary shows total estimated waste.

Pricing can be customized without rebuilding by placing a `prices.json` at `~/.sift/prices.json`. See `audit/pricing/prices.json` for the format.

## Scan history & diff

Every scan is automatically saved to `~/.sift/history/<profile>/`. Use `--diff` to compare against the previous scan:

```bash
sift cost --profile icloud-dev --diff
```

Output:
```
Diff vs 2026-05-18 09:30:
  New:      2
  Resolved: 1
  Ongoing:  32
```

History is retained for the last 30 scans per profile/command. Disable saving with `--no-save`.

## Risk matrices

### EC2

| Public IP | Open to World | IMDSv1 | Risk |
|-----------|--------------|--------|------|
| ✓ | ✓ | any | CRITICAL |
| ✗ | ✓ | any | HIGH |
| ✓ | ✗ | ✓ | HIGH |
| ✓ | ✗ | ✗ | MEDIUM |
| ✗ | ✗ | ✓ | MEDIUM |
| ✗ | ✗ | ✗ | MINIMAL |

### S3

| Public Access Blocked | Encrypted | Versioning | Logging | Risk |
|-----------------------|-----------|------------|---------|------|
| ✗ | ✗ | any | any | CRITICAL |
| ✗ | ✓ | any | any | HIGH |
| ✓ | ✗ | any | any | MEDIUM |
| ✓ | ✓ | ✗ or no logging | any | LOW |
| ✓ | ✓ | ✓ | ✓ | MINIMAL |

### RDS

| Publicly Accessible | Encrypted | Backup < 7d or No Delete Protection | Multi-AZ / Auto Upgrade | Risk |
|---------------------|-----------|--------------------------------------|------------------------|------|
| ✓ | ✗ | any | any | CRITICAL |
| ✓ | ✓ | any | any | HIGH |
| ✗ | ✗ | any | any | HIGH |
| ✗ | ✓ | ✓ | any | MEDIUM |
| ✗ | ✓ | ✗ | missing | LOW |
| ✗ | ✓ | ✗ | ✓ | MINIMAL |

### EKS

| Public Endpoint | Private Endpoint | Secrets Encrypted | Logging | Risk |
|-----------------|-----------------|-------------------|---------|------|
| ✓ | ✗ | ✗ | any | CRITICAL |
| ✓ | ✗ | ✓ | any | HIGH |
| ✓ | ✓ | any | any | MEDIUM |
| ✗ | ✓ | ✗ or disabled logs | any | LOW |
| ✗ | ✓ | ✓ | all enabled | MINIMAL |

### SageMaker Exposure

| Direct Internet Access | Public Subnet | SG Open to World | Risk |
|------------------------|--------------|-------------------|------|
| Enabled | — | — | HIGH |
| Disabled | ✓ | ✓ | HIGH |
| Disabled | ✓ | ✗ | MEDIUM |
| Disabled | ✗ | ✓ | LOW |
| Disabled | ✗ | ✗ | MINIMAL |

### IAM

#### Policy analysis (per-role)

| Condition | Risk |
|-----------|------|
| `Action=*` + `Resource=*` or AdministratorAccess/PowerUserAccess | HIGH |
| Wildcard service actions (e.g. `s3:*`) | MEDIUM |
| No findings | MINIMAL |

#### Hygiene

| Condition | Risk |
|-----------|------|
| Active access key never used or unused > 90 days | HIGH |
| Role never used or unused > 90 days | MEDIUM |

### DMS

| Publicly Accessible | Encrypted | Risk |
|---------------------|-----------|------|
| ✓ | ✗ | CRITICAL |
| ✓ | ✓ | HIGH |
| ✗ | ✗ | HIGH |
| ✗ | ✓ | MINIMAL |

### ECR

| Scan on Push | Image Tag Mutable | Risk |
|--------------|-------------------|------|
| ✗ | ✓ | HIGH |
| ✗ | ✗ | MEDIUM |
| ✓ | ✓ | LOW |
| ✓ | ✗ | MINIMAL |

### Lambda

| Condition | Risk |
|-----------|------|
| Public function URL with no auth | CRITICAL |
| Public function URL with auth | MEDIUM |
| Deprecated runtime | HIGH |

### Secrets Manager

| Condition | Risk |
|-----------|------|
| No rotation, never rotated | HIGH |
| No rotation enabled | MEDIUM |
| Rotation overdue (>90d) | MEDIUM |
| Rotation enabled and current | MINIMAL |

### DynamoDB

| Encrypted | PITR | Deletion Protection | Risk |
|-----------|------|---------------------|------|
| ✗ | any | any | HIGH |
| ✓ | ✗ | ✗ | MEDIUM |
| ✓ | ✗ | ✓ | LOW |
| ✓ | ✓ | ✗ | LOW |
| ✓ | ✓ | ✓ | MINIMAL |

### ELB

| Internet-facing | DB/Cache Port Exposed | SG Open to World | Risk |
|-----------------|----------------------|-------------------|------|
| ✓ | ✓ | ✓ | CRITICAL |
| ✓ | ✗ | ✓ | HIGH |
| ✓ | ✓ | ✗ | MEDIUM |
| ✓ | ✗ | ✗ | LOW |
| ✗ (internal) | any | any | MINIMAL |

Sensitive ports flagged: MongoDB (27017-27018), MySQL (3306), PostgreSQL (5432), Redis (6379), Elasticsearch (9200-9300), Memcached (11211), MSSQL (1433), Oracle (1521), Redshift (5439).

### Glue

| Condition | Risk |
|-----------|------|
| No catalog or connection encryption | HIGH |
| Partial encryption | MEDIUM |
| Job without security configuration | LOW |
| Fully configured | MINIMAL |

### Triage

| Condition | Risk |
|-----------|------|
| Public connections + open SG | CRITICAL |
| Public connections detected | HIGH |
| IAM HIGH + open SG | HIGH |
| Open SG or IMDSv1 | MEDIUM |
| None of the above | LOW |

### Baseline (CloudTrail / GuardDuty) — included in Triage

| Condition | Risk |
|-----------|------|
| No CloudTrail trails or logging disabled | CRITICAL |
| GuardDuty not enabled or detector disabled | CRITICAL |
| CloudTrail not multi-region | HIGH |
| CloudTrail no log file validation | MEDIUM |
| All enabled and configured | MINIMAL |

### Ops

#### Glue

| Condition | Risk |
|-----------|------|
| Crawler version ≥ 95% of limit | CRITICAL |
| Crawler version ≥ 80% of limit | HIGH |
| Crawler version ≥ 60% of limit | MEDIUM |

The crawler version limit (default 1,000,000) is fetched automatically from AWS Service Quotas to reflect any account-level increases.

### Cost

#### EC2

| Issue | Risk | Rationale |
|-------|------|-----------|
| Stopped instance | MEDIUM | EBS still incurs cost |
| Previous-gen instance | LOW | Works fine, just costs more per unit |
| Unused Elastic IP | LOW | $3.65/mo each |

#### EBS

| Issue | Risk | Rationale |
|-------|------|-----------|
| Unattached volume | MEDIUM | Pure waste, easy to snapshot+delete |
| Old snapshot (>90d) | LOW | Accumulates slowly |
| GP2 volume | LOW | ~20% savings via GP3 migration |

#### RDS

| Issue | Risk | Rationale |
|-------|------|-----------|
| Stopped instance | MEDIUM | Storage still costs, auto-restarts after 7 days |
| Oversized instance (<10% CPU) | HIGH | Continuous overspend |

#### S3

| Issue | Risk | Rationale |
|-------|------|-----------|
| No lifecycle policy | MEDIUM | Unbounded growth |

#### EKS

| Issue | Risk | Rationale |
|-------|------|-----------|
| Cluster with no node groups | HIGH | $73/mo for nothing |
| Previous-gen nodes | LOW | Same as EC2 prev-gen |
| Empty node group (desired=0) | MEDIUM | Config overhead, minor cost |

#### Network

| Issue | Risk | Rationale |
|-------|------|-----------|
| Idle NAT gateway | HIGH | ~$35/mo, zero traffic |

#### CloudWatch

| Issue | Risk | Rationale |
|-------|------|-----------|
| No retention policy | MEDIUM | $0.03/GB/mo, grows forever |

#### ECR

| Issue | Risk | Rationale |
|-------|------|-----------|
| No lifecycle policy | LOW | $0.10/GB/mo, grows slowly |

#### Secrets Manager

| Issue | Risk | Rationale |
|-------|------|-----------|
| Unused secret (>90d) | LOW | $0.40/mo each |

#### Glue

| Issue | Risk | Rationale |
|-------|------|-----------|
| Active dev endpoint | HIGH | $0.44/DPU/hr, runs 24/7, deprecated |
| Failed job | MEDIUM | Wasting DPU-hours on failures |
| Unused job (>90d) | LOW | No active cost, just clutter |
| Consider Python Shell | LOW | Optimization suggestion |
| Expensive worker type (G.2X) | MEDIUM | 2x cost if memory isn't needed |
| Overprovisioned job | MEDIUM | Paying for unused DPUs |

#### Lambda

| Issue | Risk | Rationale |
|-------|------|-----------|
| Unused function | LOW | No invocations = no cost |
| Unused provisioned concurrency | HIGH | Paying for reserved capacity with zero usage |

#### DynamoDB

| Issue | Risk | Rationale |
|-------|------|-----------|
| Provisioned mode | LOW | Consider on-demand if traffic is unpredictable |
| Unused GSI (zero items) | MEDIUM | Wasting provisioned capacity |

#### DMS

| Issue | Risk | Rationale |
|-------|------|-----------|
| Idle instance (no tasks) | HIGH | Paying for compute with zero workload |
| All tasks stopped | MEDIUM | Instance cost continues while tasks idle |
| Oversized instance (low CPU) | MEDIUM | Continuous overspend on capacity |
| Previous-gen instance | LOW | Newer gen is cheaper per unit |
| Multi-AZ enabled | LOW | 2x cost if HA isn't needed |

#### SageMaker

| Issue | Risk | Rationale |
|-------|------|-----------|
| Stopped notebook | MEDIUM | EBS storage still incurring cost |

#### ELB

| Issue | Risk | Rationale |
|-------|------|-----------|
| Idle load balancer | HIGH | ~$18/mo base cost, zero traffic |
| No target groups | MEDIUM | LB serving nothing |

## Project structure

```
sift/
├── main.go                     # Entry point
├── Makefile                    # Build script
├── cmd/                        # CLI commands (cobra)
│   ├── root.go                 # Global flags
│   ├── run.go                  # Shared audit runner + history save
│   ├── security.go             # Security audit command
│   ├── cost.go                 # Cost audit command
│   ├── ops.go                  # Ops audit command
│   └── triage.go               # Triage investigation command
├── config/
│   └── config.go               # AWS credential/profile loading
└── audit/
    ├── finding.go              # Finding struct definition
    ├── output.go               # JSON/CSV/table output formatter
    ├── thresholds.go           # Configurable thresholds
    ├── pricing/
    │   ├── pricing.go          # Price lookup (embedded + ~/.sift/prices.json override)
    │   └── prices.json         # Static pricing data (eu-west-1)
    ├── history/
    │   ├── history.go          # Scan persistence (~/.sift/history/)
    │   └── diff.go             # Delta computation between scans
    ├── progress/
    │   └── progress.go         # Progress bar utilities
    ├── security/
    │   ├── security.go         # Security audit orchestrator
    │   ├── sg.go               # Shared SG open-to-world helpers
    │   ├── ec2.go              # EC2 posture analysis
    │   ├── sagemaker.go        # SageMaker notebook + network exposure
    │   ├── s3.go               # S3 bucket audit
    │   ├── rds.go              # RDS instance audit
    │   ├── eks.go              # EKS cluster audit
    │   ├── iam.go              # IAM role policy analysis + caching
    │   ├── secrets.go          # Secrets Manager rotation audit
    │   ├── glue.go             # Glue catalog encryption + job security
    │   ├── lambda.go           # Lambda public URLs + deprecated runtimes
    │   ├── dynamodb.go         # DynamoDB encryption + PITR
    │   ├── elb.go              # ELB exposure analysis
    │   ├── dms.go              # DMS public access + encryption
    │   ├── ecr.go              # ECR scan-on-push + tag immutability
    │   ├── baseline.go         # CloudTrail + GuardDuty (used by triage)
    │   ├── network.go          # VPC flow log queries
    │   └── triage.go           # Combined investigation
    ├── ops/
    │   ├── ops.go              # Ops audit orchestrator
    │   └── glue.go             # Crawler version limit checks
    └── cost/
        ├── cost.go             # Cost audit orchestrator
        ├── ec2.go              # Stopped instances, prev-gen, unused EIPs
        ├── ebs.go              # Unattached volumes, old snapshots, GP2→GP3
        ├── rds.go              # Stopped/oversized RDS instances
        ├── s3.go               # Missing lifecycle policies + bucket size
        ├── eks.go              # Empty clusters, prev-gen nodes
        ├── network.go          # Idle NAT gateways
        ├── cloudwatch.go       # Log groups without retention
        ├── ecr.go              # Repos without lifecycle policies
        ├── secrets.go          # Unused secrets
        ├── glue.go             # Dev endpoints, job cost analysis
        ├── lambda.go           # Unused functions, provisioned concurrency
        ├── dynamodb.go         # Provisioned mode, unused GSIs
        ├── dms.go              # Idle/oversized DMS instances
        ├── elb.go              # Idle load balancers
        └── sagemaker.go        # Stopped notebooks
```

## Authentication

Sift uses the standard AWS SDK credential chain. Any method supported by the AWS SDK for Go v2 works:

- **SSO** (recommended): `aws configure sso`, then `aws sso login --profile <name>` before running sift
- **Static credentials**: `~/.aws/credentials`
- **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- **IAM roles**: EC2 instance profiles, ECS task roles

## Configuration

| Path | Description |
|------|-------------|
| `~/.sift/prices.json` | Custom pricing overrides (optional) |
| `~/.sift/history/` | Scan history (auto-created) |

## Environment variables

| Variable | Description |
|----------|-------------|
| `AWS_PROFILE` | Override default profile |
