package security

import "testing"

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
