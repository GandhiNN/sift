package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"sift/audit/history"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"
)

var fixDryRun bool

var fixCmd = &cobra.Command{
	Use:   "fix <finding-id>",
	Short: "Show or execute remediation for a finding",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		findingID := args[0]

		db, err := history.OpenDB()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		defer db.Close()

		findings, err := db.FindingHistory(findingID)
		if err != nil || len(findings) == 0 {
			fmt.Fprintf(os.Stderr, "Finding %s not found\n", findingID)
			os.Exit(2)
		}

		f := findings[0]
		if f.Remediation == nil {
			fmt.Fprintf(os.Stderr, "No remediation available for finding %s\n", findingID)
			os.Exit(2)
		}

		// Resolve template variables in command
		command := f.Remediation.Command
		command = strings.ReplaceAll(command, "{{.ResourceID}}", f.ResourceID)
		command = strings.ReplaceAll(command, "{{.Region}}", f.Region)

		// Resolve parts for composite ResourceIDs (e.g., "database/table")
		parts := strings.SplitN(f.ResourceID, "/", 2)
		if len(parts) == 2 {
			// Service-specific variable names
			switch f.Service {
			case "eks":
				command = strings.ReplaceAll(command, "{{.ClusterName}}", parts[0])
				command = strings.ReplaceAll(command, "{{.NodegroupName}}", parts[1])
			case "timestream":
				command = strings.ReplaceAll(command, "{{.DatabaseName}}", parts[0])
				command = strings.ReplaceAll(command, "{{.TableName}}", parts[1])
			case "dynamodb":
				command = strings.ReplaceAll(command, "{{.TableName}}", parts[0])
				command = strings.ReplaceAll(command, "{{.IndexName}}", parts[1])
			}
		}

		// Resolve account ID if needed
		if strings.Contains(command, "{{.AccountID}}") {
			ctx, cfg, cancel, err := buildAWSConfig()
			if err == nil {
				defer cancel()
				stsClient := sts.NewFromConfig(cfg)
				resp, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
				if err == nil {
					command = strings.ReplaceAll(
						command,
						"{{.AccountID}}",
						aws.ToString(resp.Account),
					)
				}
			}
		}

		fmt.Printf("Finding: %s/%s (%s)\n", f.Service, f.Check, f.ResourceID)
		fmt.Printf("Risk:	 %s\n", f.RiskLevel)
		fmt.Printf("Detail:	 %s\n", f.Detail)
		fmt.Printf("Action:  %s\n", f.Remediation.Action)
		fmt.Printf("Command: %s\n", command)
		fmt.Printf("Risk:    %s\n", f.Remediation.ActionRisk)

		hasPlaceholders := strings.Contains(command, "<") &&
			strings.Contains(command, ">")
		if hasPlaceholders {
			fmt.Println(
				"\n⚠ Command contains placeholders (<...>) that must be filled in manually.",
			)
		}

		if fixDryRun {
			fmt.Println("\n(dry-run: command not executed)")
			return
		}

		fmt.Print("\nExecute? [y/N] ")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(answer) != "y" {
			fmt.Println("Aborted.")
			return
		}

		cmdParts := strings.Fields(command)
		if len(cmdParts) == 0 {
			fmt.Fprintln(os.Stderr, "Empty command")
			os.Exit(2)
		}
		c := exec.Command(cmdParts[0], cmdParts[1:]...)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Command failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ Done")
	},
}

func init() {
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "Show command without executing")
	rootCmd.AddCommand(fixCmd)
}
