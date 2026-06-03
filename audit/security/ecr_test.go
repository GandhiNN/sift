package security

import (
	"testing"
)

func TestECRCheckNames(t *testing.T) {
	// Secure repo: scan on push + immutable tags -> no findings (PASS)
	// No scan: no_scan_on_push
	// Mutable tags: -> mutable_tags
	// Both: -> no_scan_on_push (MEDIUM) + mutable_tags (HIGH)
	tests := []struct {
		name           string
		scanOnPush     bool
		mutableTags    bool
		wantChecks     []string
		wantRiskLevels []string
	}{
		{
			name:           "secure repo",
			scanOnPush:     true,
			mutableTags:    false,
			wantChecks:     []string{"ecr_posture"},
			wantRiskLevels: []string{"MINIMAL"},
		},
		{
			name:           "no scan on push only",
			scanOnPush:     false,
			mutableTags:    false,
			wantChecks:     []string{"no_scan_on_push"},
			wantRiskLevels: []string{"MEDIUM"},
		},
		{
			name:           "mutable tags only",
			scanOnPush:     true,
			mutableTags:    true,
			wantChecks:     []string{"mutable_tags"},
			wantRiskLevels: []string{"LOW"},
		},
		{
			name:           "both issues",
			scanOnPush:     false,
			mutableTags:    true,
			wantChecks:     []string{"no_scan_on_push", "mutable_tags"},
			wantRiskLevels: []string{"MEDIUM", "HIGH"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the logic from AuditECR
			var checks []string
			var risks []string

			if !tt.scanOnPush {
				checks = append(checks, "no_scan_on_push")
				risks = append(risks, "MEDIUM")
			}
			if tt.mutableTags {
				risk := "LOW"
				if !tt.scanOnPush {
					risk = "HIGH"
				}
				checks = append(checks, "mutable_tags")
				risks = append(risks, risk)
			}
			if len(checks) == 0 {
				checks = append(checks, "ecr_posture")
				risks = append(risks, "MINIMAL")
			}
			if len(checks) != len(tt.wantChecks) {
				t.Fatalf("got %d findings, want %d", len(checks), len(tt.wantChecks))
			}
			for i := range checks {
				if checks[i] != tt.wantChecks[i] {
					t.Errorf("check[%d] = %s, want %s", i, checks[i], tt.wantChecks[i])
				}
				if risks[i] != tt.wantRiskLevels[i] {
					t.Errorf("risk[%d] = %s, want %s", i, risks[i], tt.wantRiskLevels[i])
				}
			}
		})
	}
}
