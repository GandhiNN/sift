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

	CostAttribution     *CostAttribution
	SecurityAttribution *SecurityAttribution
	SpendOverview       []SpendByTag

	Services []ServiceCount

	AISummary         string
	AIRecommendations []string
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
	ByValue         []TagValueCost
}

type TagValueCost struct {
	Value   string
	Cost    float64
	Percent float64
	Count   int
}

type SecurityAttribution struct {
	Tags            []string
	FullyTagged     int
	PartiallyTagged int
	Untagged        int
	TotalResources  int
	ByValue         []TagValueSecurity
}

type TagValueSecurity struct {
	Value    string
	Count    int
	Critical int
	High     int
	Percent  float64
}

type SpendByTag struct {
	Value string
	Spend float64
}

type ServiceCount struct {
	Name  string
	Count int
}
