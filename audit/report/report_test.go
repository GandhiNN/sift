package report

import "testing"

func TestFmtCost(t *testing.T) {
	tests := []struct {
		input    float64
		expected string
	}{
		{0, "0"},
		{5, "5"},
		{99, "99"},
		{999, "999"},
		{1000, "1,000"},
		{15536, "15,536"},
		{1234567, "1,234,567"},
	}
	for _, tt := range tests {
		got := fmtCost(tt.input)
		if got != tt.expected {
			t.Errorf("fmtCost(%v) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestRiskOrd(t *testing.T) {
	tests := []struct {
		level    string
		expected int
	}{
		{"CRITICAL", 4},
		{"HIGH", 3},
		{"MEDIUM", 2},
		{"LOW", 1},
		{"MINIMAL", 0},
		{"UNKNOWN", 0},
	}
	for _, tt := range tests {
		got := riskOrd(tt.level)
		if got != tt.expected {
			t.Errorf("riskOrd(%q) = %d, want %d", tt.level, got, tt.expected)
		}
	}
}

func TestParseResponse(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantSummary string
		wantActions int
	}{
		{
			name: "standard format",
			content: `SUMMARY:
The platform health is poor with multiple critical issues.

ACTIONS:
1. Fix the EKS public endpoints
2. Delete idle NAT gateways
3. Enable encryption on S3 buckets`,
			wantSummary: "The platform health is poor with multiple critical issues.",
			wantActions: 3,
		},
		{
			name:        "inline summary",
			content:     "SUMMARY: Platform is healthy. \n\nACTIONS:\n1. Monitor costs\n2. Review IAM\n3. Update nodes",
			wantSummary: "Platform is healthy.",
			wantActions: 3,
		},
		{
			name:        "no summary section",
			content:     "ACTIONS:\n1. Do something\n2. Do another\n3. Do third",
			wantSummary: "",
			wantActions: 3,
		},
		{
			name: "recommended actions header",
			content: `SUMMARY:
All good.

RECOMMENDED ACTIONS:
1. Keep monitoring
2. Reduce waste
3. Patch nodes`,
			wantSummary: "All good.",
			wantActions: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ReportData{}
			parseResponse(tt.content, r)
			if r.AISummary != tt.wantSummary {
				t.Errorf("AISummary = %q, want %q", r.AISummary, tt.wantSummary)
			}
			if len(r.AIRecommendations) != tt.wantActions {
				t.Errorf(
					"AIRecommendations count = %d, want %d",
					len(r.AIRecommendations),
					tt.wantActions,
				)
			}
		})
	}
}
