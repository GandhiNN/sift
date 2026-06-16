package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"sift/audit"
	"sift/audit/history"

	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Executive summary of latest scan findings",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := history.OpenDB()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		defer db.Close()

		// Gather findings from both modules
		var allFindings []audit.Finding
		var latestTime string
		for _, mod := range []string{"security", "cost"} {
			meta, findings, err := db.LatestScan(profile, mod)
			if err != nil || meta == nil {
				continue
			}
			if latestTime == "" || meta.Timestamp.Format("2006-01-02 15:04") > latestTime {
				latestTime = meta.Timestamp.Format("2006-01-02 15:04")
			}
			allFindings = append(allFindings, findings...)
		}

		if len(allFindings) == 0 {
			fmt.Fprintf(os.Stderr, "No scan data found. Run sift security/cost first.")
			os.Exit(2)
		}

		// Filter non-PASS
		var issues []audit.Finding
		for _, f := range allFindings {
			if f.Status != "PASS" {
				issues = append(issues, f)
			}
		}

		// Risk counts
		risks := map[string]int{}
		for _, f := range issues {
			risks[f.RiskLevel]++
		}

		// Total cost
		var totalCost float64
		for _, f := range issues {
			totalCost += f.EstimatedMonthlyCost
		}

		// Top issues by risk then cost
		sort.Slice(issues, func(i, j int) bool {
			ri := riskOrd(issues[i].RiskLevel)
			rj := riskOrd(issues[j].RiskLevel)
			if ri != rj {
				return ri > rj
			}
			return issues[i].EstimatedMonthlyCost > issues[j].EstimatedMonthlyCost
		})

		// Diff
		var diffLine string
		for _, mod := range []string{"security", "cost"} {
			_, prev, _ := db.LatestScan(profile, mod)
			_ = prev // diff requires two scans; skip if only one
		}

		// Output
		fmt.Println("=== SIFT EXECUTIVE SUMMARY ===")
		fmt.Printf("Profile: %s | %s\n\n", profile, latestTime)

		fmt.Println("RISK OVERVIEW")
		for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			if risks[level] > 0 {
				fmt.Printf("  %-10s %d\n", level+";", risks[level])
			}
		}

		if totalCost > 0 {
			fmt.Printf("\nESTIMATED WASTE: $%.0f/mo\n", totalCost)
		}

		fmt.Println("\nTOP ISSUES:")
		limit := 10
		if len(issues) < limit {
			limit = len(issues)
		}
		for i := 0; i < limit; i++ {
			f := issues[i]
			line := fmt.Sprintf(
				"  %d. [%s] %s/%s: %s",
				i+1,
				f.RiskLevel,
				f.Service,
				f.Check,
				f.Detail,
			)
			if f.EstimatedMonthlyCost > 0 {
				line += fmt.Sprintf(" ($%.0f/mo)", f.EstimatedMonthlyCost)
			}
			fmt.Println(truncateStr(line, 120))
		}

		if diffLine != "" {
			fmt.Println("\n" + diffLine)
		}

		// Services breakdown
		svcCounts := map[string]int{}
		for _, f := range issues {
			svcCounts[f.Service]++
		}
		fmt.Println("\nBY SERVICE:")
		type svcCount struct {
			name  string
			count int
		}
		var svcs []svcCount
		for k, v := range svcCounts {
			svcs = append(svcs, svcCount{k, v})
		}
		sort.Slice(svcs, func(i, j int) bool { return svcs[i].count > svcs[j].count })
		for _, s := range svcs {
			fmt.Printf("  %-16s %d issues\n", s.name, s.count)
		}

		_ = strings.Join // keep import
	},
}

func riskOrd(level string) int {
	switch level {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func init() {
	rootCmd.AddCommand(reportCmd)
}
