package report

import (
	"sift/audit"
	"sift/audit/history"
)

// ReportData holds all computed data for the executive report.
type ReportData struct {
	Profiles    []string
	Timestamp   string
	HealthScore float64

	Risks       map[string]int
	TotalWaste  float64
	TopSecurity []audit.Finding
	TopCost     []audit.Finding

	Trend *Trend

	Compliance []ComplianceScore

	Aging []history.AgingFinding

	CostAttribution *CostAttribution

	Services []ServiceCount
}

type Trend struct {
	New      int
	Resolved int
	Ongoing  int
}

type ComplianceScore struct {
	Label     string
	Percent   float64
	Compliant int
	Total     int
}

type CostAttribution struct {
	Tags            []string
	TotalCost       float64
	AttributedCost  float64
	FullyTagged     int
	PartiallyTagged int
	Untagged        int
	TotalResources  int
}

type ServiceCount struct {
	Name  string
	Count int
}
