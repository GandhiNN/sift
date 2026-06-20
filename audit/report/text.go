package report

import (
	"fmt"
	"io"
	"strings"
)

func fmtCost(v float64) string {
	s := fmt.Sprintf("%.0f", v)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

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
		fmt.Fprintf(w, "\nESTIMATED WASTE: $%s/mo\n", fmtCost(r.TotalWaste))
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
				line += fmt.Sprintf(" ($%s/mo)", fmtCost(f.EstimatedMonthlyCost))
			}
			if len(line) > 120 {
				line = line[:117] + "..."
			}
			fmt.Fprintln(w, line)
		}
	}

	fmt.Fprintf(w, "\nCOMPLIANCE:\n")
	fmt.Fprintf(w, "  (%% of resources with no issues per module)\n")
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
		fmt.Fprintf(w, "\nCOST ATTRIBUTION BY TAGS:\n")
		fmt.Fprintf(w, "  (tags: %s)\n", strings.Join(ca.Tags, ", "))
		if ca.TotalCost > 0 {
			fmt.Fprintf(
				w,
				"  %-22s %4.0f%%  $%s/mo of $%s/mo\n",
				"Fully attributable:",
				ca.AttributedCost/ca.TotalCost*100,
				fmtCost(ca.AttributedCost),
				fmtCost(ca.TotalCost),
			)
			fmt.Fprintf(
				w,
				"  %-22s %4.0f%%  $%s/mo of $%s/mo\n",
				"Unattributed cost:",
				(ca.TotalCost-ca.AttributedCost)/ca.TotalCost*100,
				fmtCost(ca.TotalCost-ca.AttributedCost),
				fmtCost(ca.TotalCost),
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
		if len(ca.ByValue) > 0 {
			fmt.Fprintf(w, "\n  BREAKDOWN:\n")
			fmt.Fprintf(w, "  (tags: %s)\n", strings.Join(ca.Tags, ", "))
			for _, v := range ca.ByValue {
				fmt.Fprintf(w, "  %-24s $%9s/mo  %5.0f%%\n", v.Value, fmtCost(v.Cost), v.Percent)
			}
		}
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

	if r.SecurityAttribution != nil && len(r.SecurityAttribution.ByValue) > 0 {
		sa := r.SecurityAttribution
		fmt.Fprintf(w, "\nSECURITY ATTRIBUTION BY TAGS:\n")
		fmt.Fprintf(w, "  (tags: %s)\n", strings.Join(sa.Tags, ", "))
		fmt.Fprintf(
			w,
			"  %-22s %4.0f%% %d of %d findings\n",
			"Fully tagged:",
			float64(sa.FullyTagged)/float64(sa.TotalResources)*100,
			sa.FullyTagged,
			sa.TotalResources,
		)
		if sa.PartiallyTagged > 0 {
			fmt.Fprintf(
				w,
				"  %-22s %4.0f%% %d of %d findings\n",
				"Partially tagged:",
				float64(sa.PartiallyTagged)/float64(sa.TotalResources)*100,
				sa.PartiallyTagged,
				sa.TotalResources,
			)
		}
		fmt.Fprintf(
			w,
			"  %-22s %4.0f%% %d of %d findings\n",
			"Untagged:",
			float64(sa.Untagged)/float64(sa.TotalResources)*100,
			sa.Untagged,
			sa.TotalResources,
		)
		fmt.Fprintf(w, "\n BREAKDOWN:\n")
		fmt.Fprintf(w, "  (tags: %s)\n", strings.Join(sa.Tags, ", "))
		for _, v := range sa.ByValue {
			fmt.Fprintf(w, "  %-24s %4d issues  %4.0f%%", v.Value, v.Count, v.Percent)
			if v.Critical > 0 || v.High > 0 {
				fmt.Fprintf(w, "  (CRITICAL:%d HIGH:%d)", v.Critical, v.High)
			}
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintf(w, "\n# OF ISSUES BY SERVICE:\n")
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
