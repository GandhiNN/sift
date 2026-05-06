package security

import (
	"testing"
)

func TestEc2Risk(t *testing.T) {
	tests := []struct {
		name string
		inst ec2Instance
		want string
	}{
		{"public+open", ec2Instance{publicIP: true, openToWorld: true}, "CRITICAL"},
		{"open only", ec2Instance{openToWorld: true}, "HIGH"},
		{"public+imdsv1", ec2Instance{publicIP: true, imdsV1: true}, "HIGH"},
		{"public only", ec2Instance{publicIP: true}, "MEDIUM"},
		{"imdsv1 only", ec2Instance{imdsV1: true}, "MEDIUM"},
		{"clean", ec2Instance{}, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ec2Risk(tt.inst); got != tt.want {
				t.Errorf("ec2Risk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestS3Risk(t *testing.T) {
	tests := []struct {
		name          string
		publicBlocked bool
		encrypted     bool
		versioning    bool
		logging       bool
		want          string
	}{
		{"no public block no encryption", false, false, true, true, "CRITICAL"},
		{"no public block with encryption", false, true, true, true, "HIGH"},
		{"public blocked no encryption", true, false, true, true, "MEDIUM"},
		{"no versioning", true, true, false, true, "LOW"},
		{"no logging", true, true, true, false, "LOW"},
		{"fully configured", true, true, true, true, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s3Risk(tt.publicBlocked, tt.encrypted, tt.versioning, tt.logging); got != tt.want {
				t.Errorf("s3Risk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRdsRisk(t *testing.T) {
	tests := []struct {
		name        string
		public      bool
		encrypted   bool
		backup      int32
		delProtect  bool
		multiAZ     bool
		autoUpgrade bool
		want        string
	}{
		{"public no encryption", true, false, 7, true, true, true, "CRITICAL"},
		{"public encrypted", true, true, 7, true, true, true, "HIGH"},
		{"not encrypted", false, false, 7, true, true, true, "HIGH"},
		{"low backup", false, true, 3, true, true, true, "MEDIUM"},
		{"no delete protection", false, true, 7, false, true, true, "MEDIUM"},
		{"no multi-az", false, true, 7, true, false, true, "LOW"},
		{"no auto upgrade", false, true, 7, true, true, false, "LOW"},
		{"fully configured", false, true, 7, true, true, true, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rdsRisk(tt.public, tt.encrypted, tt.backup, tt.delProtect, tt.multiAZ, tt.autoUpgrade); got != tt.want {
				t.Errorf("rdsRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestEksRisk(t *testing.T) {
	tests := []struct {
		name            string
		publicEP        bool
		privateEP       bool
		secretsEnc      bool
		hasDisabledLogs bool
		want            string
	}{
		{"public no private no secrets", true, false, false, false, "CRITICAL"},
		{"public no private with secrets", true, false, true, false, "HIGH"},
		{"public with private", true, true, true, false, "MEDIUM"},
		{"private no secrets", false, true, false, false, "LOW"},
		{"private disabled logs", false, true, true, true, "LOW"},
		{"fully configured", false, true, true, false, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eksRisk(tt.publicEP, tt.privateEP, tt.secretsEnc, tt.hasDisabledLogs); got != tt.want {
				t.Errorf("eksRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSecretsRisk(t *testing.T) {
	tests := []struct {
		name             string
		rotationEnabled  bool
		rotationOverdue  bool
		daysSinceRotated int
		want             string
	}{
		{"no rotation never rotated", false, false, -1, "HIGH"},
		{"no rotation was rotated", false, false, 30, "MEDIUM"},
		{"rotation overdue", true, true, 120, "MEDIUM"},
		{"rotation enabled and current", true, false, 30, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secretsRisk(tt.rotationEnabled, tt.rotationOverdue, tt.daysSinceRotated); got != tt.want {
				t.Errorf("secretsRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestGlueCatalogRisk(t *testing.T) {
	tests := []struct {
		name             string
		catalogEncrypted bool
		connEncrypted    bool
		want             string
	}{
		{"no encryption", false, false, "HIGH"},
		{"partial catalog only", true, false, "MEDIUM"},
		{"partial conn only", false, true, "MEDIUM"},
		{"fully encrypted", true, true, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := glueCatalogRisk(tt.catalogEncrypted, tt.connEncrypted); got != tt.want {
				t.Errorf("glueCatalogRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDynamoDBRisk(t *testing.T) {
	tests := []struct {
		name               string
		encrypted          bool
		pitr               bool
		deletionProtection bool
		want               string
	}{
		{"no encryption", false, true, true, "HIGH"},
		{"no encryption no pitr no delete", false, false, false, "HIGH"},
		{"no pitr no delete protection", true, false, false, "MEDIUM"},
		{"no pitr with delete protection", true, false, true, "LOW"},
		{"pitr no delete protection", true, true, false, "LOW"},
		{"fully configured", true, true, true, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk, _ := dynamoDBRisk(tt.encrypted, tt.pitr, tt.deletionProtection)
			if risk != tt.want {
				t.Errorf("dynamoDBRisk() = %s, want %s", risk, tt.want)
			}
		})
	}
}

func TestTriageRisk(t *testing.T) {
	tests := []struct {
		name        string
		openToWorld bool
		imdsV1      bool
		iamRisk     string
		connCount   int
		want        string
	}{
		{"public conns + open", true, false, "", 5, "CRITICAL"},
		{"public conns only", false, false, "", 3, "HIGH"},
		{"iam HIGH + open", true, false, "HIGH", 0, "HIGH"},
		{"open to world", true, false, "", 0, "MEDIUM"},
		{"imdsv1", false, true, "", 0, "MEDIUM"},
		{"clean", false, false, "", 0, "LOW"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := triageRisk(tt.openToWorld, tt.imdsV1, tt.iamRisk, tt.connCount); got != tt.want {
				t.Errorf("triageRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestStatusFromRisk(t *testing.T) {
	if got := statusFromRisk("MINIMAL"); got != "PASS" {
		t.Errorf("statusFromRisk(MINIMAL) = %s, want PASS", got)
	}
	for _, risk := range []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		if got := statusFromRisk(risk); got != "FAIL" {
			t.Errorf("statusFromRisk(%s) = %s, want FAIL", risk, got)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"10.0.0.1", true},
		{"172.16.5.1", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.2.3.4", false},
		{"invalid", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := isPrivateIP(tt.addr); got != tt.want {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestCheckPolicyDocument(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantLen int
		issue   string
	}{
		{
			"wildcard admin",
			`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			1, "wildcard_admin",
		},
		{
			"wildcard service action",
			`{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::*"}]}`,
			1, "wildcard_action",
		},
		{
			"deny ignored",
			`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
			0, "",
		},
		{
			"safe policy",
			`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*"}]}`,
			0, "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := checkPolicyDocument(tt.doc, "test-policy", "inline")
			if len(findings) != tt.wantLen {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantLen)
			}
			if tt.wantLen > 0 && findings[0].Issue != tt.issue {
				t.Errorf("got issue %s, want %s", findings[0].Issue, tt.issue)
			}
		})
	}
}

func TestToStringSlice(t *testing.T) {
	if got := toStringSlice("single"); len(got) != 1 || got[0] != "single" {
		t.Errorf("toStringSlice(string) = %v", got)
	}
	if got := toStringSlice([]interface{}{"a", "b"}); len(got) != 2 {
		t.Errorf("toStringSlice([]interface{}) = %v", got)
	}
	if got := toStringSlice(42); got != nil {
		t.Errorf("toStringSlice(int) = %v, want nil", got)
	}
}
