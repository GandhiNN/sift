package audit

import "testing"

func TestFilterByRisk(t *testing.T) {
	findings := []Finding{
		{RiskLevel: "MINIMAL"},
		{RiskLevel: "LOW"},
		{RiskLevel: "MEDIUM"},
		{RiskLevel: "HIGH"},
		{RiskLevel: "CRITICAL"},
	}

	tests := []struct {
		minRisk string
		want    int
	}{
		{"MINIMAL", 5},
		{"LOW", 4},
		{"MEDIUM", 3},
		{"HIGH", 2},
		{"CRITICAL", 1},
	}
	for _, tt := range tests {
		t.Run(tt.minRisk, func(t *testing.T) {
			result := filterByRisk(findings, tt.minRisk).([]Finding)
			if len(result) != tt.want {
				t.Errorf(
					"filterByRisk(%s) returned %d findings, want %d",
					tt.minRisk,
					len(result),
					tt.want,
				)
			}
		})
	}
}

func TestFilterByRiskCaseInsensitive(t *testing.T) {
	findings := []Finding{
		{RiskLevel: "HIGH"},
		{RiskLevel: "CRITICAL"},
	}
	result := filterByRisk(findings, "high").([]Finding)
	if len(result) != 2 {
		t.Errorf("filterByRisk(high) returned %d, want 2", len(result))
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	if got := truncate("this is a long string", 10); got != "this is..." {
		t.Errorf("truncante long = %q", got)
	}
}

func TestHasHighRiskFindings(t *testing.T) {
	if HasHighRiskFindings([]Finding{{RiskLevel: "MEDIUM"}}) {
		t.Error("MEDIUM should not be high risk")
	}
	if !HasHighRiskFindings([]Finding{{RiskLevel: "HIGH"}}) {
		t.Error("HIGH should be high risk")
	}
	if !HasHighRiskFindings([]Finding{{RiskLevel: "CRITICAL"}}) {
		t.Error("CRITICAL should be high risk")
	}
}
