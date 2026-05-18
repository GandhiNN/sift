package cmd

import (
	"context"
	"strings"

	"sift/audit"
	"sift/audit/ops"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"
)

var (
	opsServices string
	opsCheck    string
)

var validOpsServices = map[string]bool{
	"glue": true,
}

var opsCmd = &cobra.Command{
	Use:   "ops",
	Short: "Audit operational risks and service limits",
	Run: func(cmd *cobra.Command, args []string) {
		if opsCheck != "" {
			checks := strings.Split(opsCheck, ",")
			runAuditWithChecks("ops", opsServices, validOpsServices, ops.Audit, checks)
		} else {
			runAudit("ops", opsServices, validOpsServices, ops.Audit)
		}
	},
}

func init() {
	opsCmd.Flags().
		StringVar(&opsServices, "service", "", "Comma-separated services to audit (glue). Default: all")
	opsCmd.Flags().
		StringVar(&opsCheck, "check", "", "Comma-separated checks to run (e.g. table_versions,crawlers,job_versions)")
	rootCmd.AddCommand(opsCmd)
}

func runAuditWithChecks(
	command, serviceFlag string,
	validServices map[string]bool,
	fn auditFunc,
	checks []string,
) {
	// Inject checks into context via a wrapper
	origFn := fn
	fn = func(ctx context.Context, cfg aws.Config, services []string) ([]audit.Finding, error) {
		ctx = audit.WithChecks(ctx, checks)
		return origFn(ctx, cfg, services)
	}
	runAudit(command, serviceFlag, validServices, fn)
}
