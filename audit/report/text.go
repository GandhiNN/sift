package report

import (
	"fmt"
	"io"
	"strings"
)

func RenderText(w io.Writer, r *ReportData) {
	fmt.Fprintf(w, "=== SIFT EXECUTIVE SUMMARY ===\n")
	fmt.Fprintf(w, "Profiles: %s | %s\n", strings.Join(r.Profiles, ", "), r.Timestamp)

	fmt.Fprintf(w, "\nPLATFORM HEALTH: %.0f/100\n", r.HealthScore)

	fmt.Fprintf(w, "\nRISK OVERVIEW\n")
	for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if r.Risks[level] > 0 {
			fmt.Fprintf(w, "  %-10s %d\n", level+":", r.Risks[level])
		}
	}

	if r.TotalWaste > 0 {
		fmt.Fprintf(w, "\nESTIMATED WASTE: $%.0f/mo\n", r.TotalWaste)
	}

	if r.Trend != nil {
		fmt.Fprintf(w, "\nTREND (vs previous scan):\n")
		fmt.Fprintf(w, "  %-22s %d\n", "New issues:", r.Trend.New)
		fmt.Fprintf(w, "  %-22s %d\n", "Resolved:", r.Trend.Resolved)
		fmt.Fprintf(w, "  %-22s %d\n", "Ongoing:", r.Trend.Ongoing)
	}

	if len(r.TopSecurity) > 0 {
		fmt.Fprintf(w, "\nTOP SECURITY ISSUES:\n")
		for i, f := range r.TopSecurity {
			line := fmt.Sprintf(
				"  %d. [%s] %s/%s: %s",
				i+1,
				f.RiskLevel,
				f.Service,
				f.Check,
				f.Detail,
			)
			if len(line) > 120 {
				line = line[:117] + "..."
			}
			fmt.Fprintln(w, line)
		}
	}

	if len(r.TopCost) > 0 {
		fmt.Fprintf(w, "\nTOP COST ISSUES:\n")
		for i, f := range r.TopCost {
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
			if len(line) > 120 {
				line = line[:117] + "..."
			}
			fmt.Fprintln(w, line)
		}
	}

	fmt.Fprintf(w, "\nCOMPLIANCE:\n")
	for _, c := range r.Compliance {
		fmt.Fprintf(
			w,
			"  %-12s %.0f%% (%d of %d resources fully compliant)\n",
			c.Label+":",
			c.Percent,
			c.Compliant,
			c.Total,
		)
	}

	if len(r.Aging) > 0 {
		fmt.Fprintf(w, "\nAGING (open >7 days): %d findings\n", len(r.Aging))
		limit := 5
		if len(r.Aging) < limit {
			limit = len(r.Aging)
		}
		for _, a := range r.Aging[:limit] {
			fmt.Fprintf(
				w,
				"  [%s] %s/%s: %dd old - %s\n",
				a.RiskLevel,
				a.Service,
				a.Check,
				a.AgeDays,
				a.ResourceID,
			)
		}
	}

	if r.CostAttribution != nil {
		ca := r.CostAttribution
		fmt.Fprintf(w, "\nCOST ATTRIBUTION (by %s):\n", strings.Join(ca.Tags, ", "))
		if ca.TotalCost > 0 {
			fmt.Fprintf(
				w,
				"  %-22s %4.0f%%  $%.0f/mo of $%.0f/mo\n",
				"Fully attributable:",
				ca.AttributedCost/ca.TotalCost*100,
				ca.AttributedCost,
				ca.TotalCost,
			)
			fmt.Fprintf(
				w,
				"  %-22s %4.0f%%  $%.0f/mo of $%.0f/mo\n",
				"Unattributed cost:",
				(ca.TotalCost-ca.AttributedCost)/ca.TotalCost*100,
				ca.TotalCost-ca.AttributedCost,
				ca.TotalCost,
			)
		}
		fmt.Fprintf(
			w,
			"  %-22s %4.0f%%  %d of %d resources\n",
			"Fully tagged:",
			float64(ca.FullyTagged)/float64(ca.TotalResources)*100,
			ca.FullyTagged,
			ca.TotalResources,
		)
		if ca.PartiallyTagged > 0 {
			fmt.Fprintf(
				w,
				"  %-22s %4.0f%%  %d of %d resources\n",
				"Partially tagged:",
				float64(ca.PartiallyTagged)/float64(ca.TotalResources)*100,
				ca.PartiallyTagged,
				ca.TotalResources,
			)
		}
		fmt.Fprintf(
			w,
			"  %-22s %4.0f%%  %d of %d resources\n",
			"Untagged:",
			float64(ca.Untagged)/float64(ca.TotalResources)*100,
			ca.Untagged,
			ca.TotalResources,
		)
	}

	fmt.Fprintf(w, "\nBY SERVICE:\n")
	for _, s := range r.Services {
		fmt.Fprintf(w, "  %-16s %d issues\n", s.Name, s.Count)
	}

	if r.AISummary != "" {
		fmt.Fprintf(w, "\nAI SUMMARY:\n  %s\n", r.AISummary)
	}
	if len(r.AIRecommendations) > 0 {
		fmt.Fprintf(w, "\nAI RECOMMENDED ACTIONS:\n")
		for i, a := range r.AIRecommendations {
			fmt.Fprintf(w, "  %d. %s\n", i+1, a)
		}
	}
}
