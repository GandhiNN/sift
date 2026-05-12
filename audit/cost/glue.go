package cost

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
)

type glueCostJob struct {
	name string
	tags map[string]string
}

func parseGlueCostJob(ctx context.Context, client *glue.Client, job gluetypes.Job) glueCostJob {
	g := glueCostJob{name: aws.ToString(job.Name)}
	tagResp, err := client.GetTags(ctx, &glue.GetTagsInput{ResourceArn: job.Name})
	if err == nil {
		g.tags = tagResp.Tags
	}
	return g
}

func AuditGlueCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := glue.NewFromConfig(cfg)
	var findings []audit.Finding

	// Idle dev endpoints
	devCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	devResp, err := client.GetDevEndpoints(devCtx, &glue.GetDevEndpointsInput{})
	if err == nil {
		for _, ep := range devResp.DevEndpoints {
			name := aws.ToString(ep.EndpointName)
			dpus := ep.NumberOfNodes
			findings = append(findings, audit.Finding{
				Service:    "glue_dev_endpoint",
				ResourceID: name,
				Check:      "active_dev_endpoint",
				Status:     "WARN",
				Detail:     fmt.Sprintf("dpus=%d, ~$%.2f/hr", dpus, float64(dpus)*0.44),
				RiskLevel:  "HIGH",
			})
		}
	}

	// Collect all jobs
	spinner := progress.NewSpinner(ctx, "Collecting Glue jobs")
	var allJobs []gluetypes.Job
	jobInput := &glue.GetJobsInput{}
	for {
		jobsResp, err := client.GetJobs(ctx, jobInput)
		if err != nil {
			findings = append(findings, audit.ErrorFinding("glue", "jobs", "list_jobs", err))
			break
		}
		allJobs = append(allJobs, jobsResp.Jobs...)
		spinner.Add(len(jobsResp.Jobs))
		if jobsResp.NextToken == nil {
			break
		}
		jobInput.NextToken = jobsResp.NextToken
	}
	spinner.Finish()

	if len(allJobs) == 0 {
		return findings, nil
	}

	bar := progress.NewBar(ctx, int64(len(allJobs)), "Auditing Glue jobs")
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for _, job := range allJobs {
		wg.Add(1)
		go func(job gluetypes.Job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			g := parseGlueCostJob(ctx, client, job)
			jobFindings := auditGlueJob(ctx, client, job, g.tags)
			if len(jobFindings) > 0 {
				mu.Lock()
				findings = append(findings, jobFindings...)
				mu.Unlock()
			}
			bar.Add(1)
		}(job)
	}
	wg.Wait()

	return findings, nil
}

func auditGlueJob(
	ctx context.Context,
	client *glue.Client,
	job gluetypes.Job,
	tags map[string]string,
) []audit.Finding {
	name := aws.ToString(job.Name)
	runsResp, err := client.GetJobRuns(ctx, &glue.GetJobRunsInput{
		JobName:    &name,
		MaxResults: aws.Int32(1),
	})
	if err != nil {
		return []audit.Finding{audit.ErrorFinding("glue_job", name, "get_job_runs", err)}
	}
	if len(runsResp.JobRuns) == 0 {
		return nil
	}

	lastRun := runsResp.JobRuns[0]
	var findings []audit.Finding

	if string(lastRun.JobRunState) == "FAILED" {
		findings = append(findings, audit.Finding{
			Service:    "glue_job",
			ResourceID: name,
			Tags:       tags,
			Check:      "failed_job",
			Status:     "WARN",
			Detail:     fmt.Sprintf("last run failed: %s", aws.ToString(lastRun.ErrorMessage)),
			RiskLevel:  "MEDIUM",
		})
	}

	if lastRun.CompletedOn != nil {
		days := int(time.Since(*lastRun.CompletedOn).Hours() / 24)
		if days > audit.GetThresholds(ctx).UnusedDays {
			findings = append(findings, audit.Finding{
				Service:    "glue_job",
				ResourceID: name,
				Tags:       tags,
				Check:      "unused_job",
				Status:     "WARN",
				Detail:     fmt.Sprintf("last run %d days ago", days),
				RiskLevel:  "LOW",
			})
		}
	}

	workers := aws.ToInt32(job.NumberOfWorkers)
	if job.Command != nil && aws.ToString(job.Command.Name) == "glueetl" && workers <= 2 &&
		lastRun.ExecutionTime < 600 {
		findings = append(findings, audit.Finding{
			Service:    "glue_job",
			ResourceID: name,
			Tags:       tags,
			Check:      "consider_python_shell",
			Status:     "WARN",
			Detail: fmt.Sprintf(
				"workers=%d, runtime=%ds, small Spark job could be Python Shell ($0.0625 vs $0.44/DPU/hr)",
				workers,
				lastRun.ExecutionTime,
			),
			RiskLevel: "LOW",
		})
	}

	if string(job.WorkerType) == "G.2X" {
		findings = append(findings, audit.Finding{
			Service:    "glue_job",
			ResourceID: name,
			Tags:       tags,
			Check:      "expensive_worker_type",
			Status:     "WARN",
			Detail:     "using G.2X workers (8vCPU/32GB at $0.88/DPU/hr), consider G.1X if memory allows",
			RiskLevel:  "MEDIUM",
		})
	}

	if string(lastRun.JobRunState) == "SUCCEEDED" && lastRun.ExecutionTime > 0 {
		allocated := aws.ToFloat64(lastRun.MaxCapacity)
		if allocated == 0 {
			allocated = float64(aws.ToInt32(lastRun.NumberOfWorkers))
		}
		if allocated > 0 {
			dpuSeconds := aws.ToFloat64(lastRun.DPUSeconds)
			maxDPUSeconds := allocated * float64(lastRun.ExecutionTime)
			if maxDPUSeconds > 0 {
				utilization := dpuSeconds / maxDPUSeconds * 100
				if utilization < 30 {
					findings = append(findings, audit.Finding{
						Service:    "glue_job",
						ResourceID: name,
						Tags:       tags,
						Check:      "overprovisioned_job",
						Status:     "WARN",
						Detail: fmt.Sprintf(
							"allocated=%.0f DPUs, utilization=%.0f%%, consider reducing workers",
							allocated,
							utilization,
						),
						RiskLevel: "MEDIUM",
					})
				}
			}
		}
	}

	return findings
}
