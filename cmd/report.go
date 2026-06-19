package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

		// Determine profiles to query
		var profiles []string
		if cmd.Flags().Changed("profile") {
			profiles = strings.Split(profile, ",")
		} else {
			// Query all profiles from DB
			scans, _ := db.RecentScans(100)
			seen := map[string]bool{}
			for _, s := range scans {
				if !seen[s.Profile] {
					seen[s.Profile] = true
					profiles = append(profiles, s.Profile)
				}
			}
		}

		// Gather findings from both modules
		var allFindings []audit.Finding
		var latestTime string
		for _, p := range profiles {
			for _, mod := range []string{"security", "cost", "governance"} {
				meta, findings, err := db.LatestScan(strings.TrimSpace(p), mod)
				if err != nil || meta == nil {
					continue
				}
				if latestTime == "" || meta.Timestamp.Format("2006-01-02 15:04") > latestTime {
					latestTime = meta.Timestamp.Format("2006-01-02 15:04")
				}
				for i := range findings {
					findings[i].Module = mod
					findings[i].Region = strings.TrimSpace(p) // use profile as region for grouping
				}
				allFindings = append(allFindings, findings...)
			}
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
		for _, mod := range []string{"security", "cost", "governance"} {
			_, prev, _ := db.LatestScan(profile, mod)
			_ = prev // diff requires two scans; skip if only one
		}

		// Output
		fmt.Println("=== SIFT EXECUTIVE SUMMARY ===")
		fmt.Printf("Profiles: %s | %s\n\n", strings.Join(profiles, ", "), latestTime)

		fmt.Println("RISK OVERVIEW")
		for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			if risks[level] > 0 {
				fmt.Printf("  %-10s %d\n", level+":", risks[level])
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

		// Platform health score (risk-weighted)
		totalResources := map[string]bool{}
		var penalty float64
		for _, f := range allFindings {
			if f.ResourceID == "" {
				continue
			}
			totalResources[f.ResourceID] = true
			switch f.RiskLevel {
			case "CRITICAL":
				penalty += 4
			case "HIGH":
				penalty += 3
			case "MEDIUM":
				penalty += 2
			case "LOW":
				penalty += 1
			}
		}
		if len(totalResources) > 0 {
			// Max possible penalty: every resource has one CRITICAL finding
			maxPenalty := float64(len(totalResources)) * 4
			health := 100 - (penalty/maxPenalty)*100
			if health < 0 {
				health = 0
			}
			fmt.Printf("\nPLATFORM HEALTH: %.0f/100\n", health)
		}

		// Compliance score
		fmt.Println("\nCOMPLIANCE:")
		for _, mod := range []string{"security", "cost", "governance"} {
			resources := map[string]bool{}    // all resources
			nonCompliant := map[string]bool{} // resources with issues
			for _, f := range allFindings {
				if f.Module != mod || f.ResourceID == "" {
					continue
				}
				resources[f.ResourceID] = true
				if f.Status != "PASS" {
					nonCompliant[f.ResourceID] = true
				}
			}
			total := len(resources)
			if total > 0 {
				compliant := total - len(nonCompliant)
				pct := float64(compliant) / float64(total) * 100
				label := mod
				if mod == "governance" {
					label = "tagging"
				}
				fmt.Printf(
					"  %-12s %.0f%% (%d of %d resources fully compliant)\n",
					label+":",
					pct,
					compliant,
					total,
				)
			}
		}

		// Services breakdown
		svcCounts := map[string]int{}
		for _, f := range issues {
			svcCounts[f.Service]++
		}

		// Aging findings
		aging, _ := db.AgingFindings(7)
		if len(aging) > 0 {
			fmt.Printf("\nAGING (open >7 days): %d findings\n", len(aging))
			limit := 5
			if len(aging) < limit {
				limit = len(aging)
			}
			for _, a := range aging[:limit] {
				fmt.Printf(
					"  [%s] %s/%s: %dd old - %s\n",
					a.RiskLevel,
					a.Service,
					a.Check,
					a.AgeDays,
					truncateStr(a.ResourceID, 30),
				)
			}
		}

		// Cost attribution based on `cost_tags` from tagging config
		costTags := []string{"Project"}
		if home, err := os.UserHomeDir(); err == nil {
			if data, err := os.ReadFile(filepath.Join(home, ".sift", "tagging.json")); err == nil {
				var tc struct {
					CostTags []string `json:"cost_tags"`
				}
				if json.Unmarshal(data, &tc) == nil && len(tc.CostTags) > 0 {
					costTags = tc.CostTags
				}
			}
		}
		var totalCostAttr, attrCost float64
		var fullyTagged, partiallyTagged, untagged int
		for _, f := range allFindings {
			if f.Module != "cost" || f.Status == "PASS" {
				continue
			}
			totalCostAttr += f.EstimatedMonthlyCost
			if len(f.Tags) == 0 {
				untagged++
				continue
			}
			hasAll := true
			hasAny := false
			for _, tag := range costTags {
				if _, ok := f.Tags[tag]; ok {
					hasAny = true
				} else {
					hasAll = false
				}
			}
			if hasAll {
				fullyTagged++
				attrCost += f.EstimatedMonthlyCost
			} else if hasAny {
				partiallyTagged++
				attrCost += f.EstimatedMonthlyCost
			} else {
				untagged++
			}
		}
		total := fullyTagged + partiallyTagged + untagged
		if total > 0 {
			fmt.Printf("\nCOST ATTRIBUTION (by %s):\n", strings.Join(costTags, ", "))
			if totalCostAttr > 0 {
				fmt.Printf(
					"  %-22s %4.0f%%  $%.0f/mo of $%.0f/mo\n", "Fully attributable:",
					attrCost/totalCostAttr*100,
					attrCost,
					totalCostAttr,
				)
				fmt.Printf(
					"  %-22s %4.0f%%   $%.0f/mo of $%.0f/mo\n",
					"Unattributed cost:",
					(totalCostAttr-attrCost)/totalCostAttr*100,
					totalCostAttr-attrCost,
					totalCostAttr,
				)
			}
			fmt.Printf(
				"  %-22s %4.0f%%   %d of %d resources\n",
				"Fully tagged:",
				float64(fullyTagged)/float64(total)*100,
				fullyTagged,
				total,
			)
			if partiallyTagged > 0 {
				fmt.Printf(
					"  %-22s %4.0f%%   %d of %d resources\n",
					"Partially tagged:",
					float64(partiallyTagged)/float64(total)*100,
					partiallyTagged,
					total,
				)
			}
			fmt.Printf(
				"  %-22s %4.0f%%   %d of %d resources\n",
				"Untagged:",
				float64(untagged)/float64(total)*100,
				untagged,
				total,
			)
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
