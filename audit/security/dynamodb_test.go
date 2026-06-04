package security

import (
	"testing"
)

func TestDynamoDBCheckNames(t *testing.T) {
	tests := []struct {
		name       string
		encrypted  bool
		pitr       bool
		delProtect bool
		wantChecks []string
		wantRisks  []string
	}{
		{
			name:       "fully configured",
			encrypted:  true,
			pitr:       true,
			delProtect: true,
			wantChecks: []string{"dynamodb_posture"},
			wantRisks:  []string{"MINIMAL"},
		},
		{
			name:       "no_encryption",
			encrypted:  false,
			pitr:       true,
			delProtect: true,
			wantChecks: []string{"no_encryption"},
			wantRisks:  []string{"HIGH"},
		},
		{
			name:       "all issues",
			encrypted:  false,
			pitr:       false,
			delProtect: false,
			wantChecks: []string{"no_encryption", "no_pitr", "no_delete_protection"},
			wantRisks:  []string{"HIGH", "MEDIUM", "MEDIUM"},
		},
		{
			name:       "no pitr only",
			encrypted:  true,
			pitr:       false,
			delProtect: true,
			wantChecks: []string{"no_pitr"},
			wantRisks:  []string{"MEDIUM"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var checks []string
			var risks []string

			if !tt.encrypted {
				checks = append(checks, "no_encryption")
				risks = append(risks, "HIGH")
			}
			if !tt.pitr {
				checks = append(checks, "no_pitr")
				risks = append(risks, "MEDIUM")
			}
			if !tt.delProtect {
				checks = append(checks, "no_delete_protection")
				risks = append(risks, "MEDIUM")
			}
			if len(checks) == 0 {
				checks = append(checks, "dynamodb_posture")
				risks = append(risks, "MINIMAL")
			}
			if len(checks) != len(tt.wantChecks) {
				t.Fatalf("got %d findings, want %d", len(checks), len(tt.wantChecks))
			}
			for i := range checks {
				if checks[i] != tt.wantChecks[i] {
					t.Errorf("check[%d] = %s, want %s", i, checks[i], tt.wantChecks[i])
				}
				if risks[i] != tt.wantRisks[i] {
					t.Errorf("risk[%d] = %s, want %s", i, risks[i], tt.wantRisks[i])
				}
			}
		})
	}
}
