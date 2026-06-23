package history

import (
	"testing"

	"sift/audit"
)

func TestComputeDiff_Basic(t *testing.T) {
	prev := []audit.Finding{
		{
			Service:    "ec2",
			ResourceID: "i-111",
			Check:      "public_ip",
			Status:     "WARN",
			RiskLevel:  "HIGH",
			Region:     "eu-west-1",
		},
		{
			Service:    "s3",
			ResourceID: "bucket-1",
			Check:      "encryption",
			Status:     "WARN",
			RiskLevel:  "MEDIUM",
			Region:     "eu-west-1",
		},
	}
	curr := []audit.Finding{
		{
			Service:    "ec2",
			ResourceID: "i-111",
			Check:      "public_ip",
			Status:     "WARN",
			RiskLevel:  "HIGH",
			Region:     "eu-west-1",
		},
		{
			Service:    "rds",
			ResourceID: "db-1",
			Check:      "public_access",
			Status:     "WARN",
			RiskLevel:  "CRITICAL",
			Region:     "eu-west-1",
		},
	}

	d := ComputeDiff(prev, curr)

	if len(d.Ongoing) != 1 {
		t.Errorf("Ongoing = %d, want 1", len(d.Ongoing))
	}
	if len(d.New) != 1 {
		t.Errorf("New = %d, want 1", len(d.New))
	}
	if len(d.Resolved) != 1 {
		t.Errorf("Resolved = %d, want 1", len(d.Resolved))
	}
	if len(d.Resolved) > 0 && d.Resolved[0].Service != "s3" {
		t.Errorf("Resolved[0].Service = %q, want s3", d.Resolved[0].Service)
	}
}

func TestComputeDiff_ExcludesErroredServices(t *testing.T) {
	prev := []audit.Finding{
		{
			Service:    "eks",
			ResourceID: "cluster-1",
			Check:      "public_endpoint",
			Status:     "WARN",
			RiskLevel:  "HIGH",
			Region:     "eu-west-1",
		},
		{
			Service:    "ec2",
			ResourceID: "i-111",
			Check:      "public_ip",
			Status:     "WARN",
			RiskLevel:  "HIGH",
			Region:     "eu-west-1",
		},
	}
	curr := []audit.Finding{
		{
			Service:    "eks",
			ResourceID: "cluster-1",
			Check:      "service_error",
			Status:     "ERROR",
			RiskLevel:  "UNKNOWN",
			Region:     "eu-west-1",
		},
		{
			Service:    "ec2",
			ResourceID: "i-111",
			Check:      "public_ip",
			Status:     "WARN",
			RiskLevel:  "HIGH",
			Region:     "eu-west-1",
		},
	}

	d := ComputeDiff(prev, curr)

	// eks errored - should not appear as resolved
	for _, f := range d.Resolved {
		if f.Service == "eks" {
			t.Error("errored service 'eks' should not appear in Resolved")
		}
	}
	if len(d.Ongoing) != 1 {
		t.Errorf("Ongoing = %d, want 1 (ec2)", len(d.Ongoing))
	}
}

func TestComputeDiff_PassFindingsIgnored(t *testing.T) {
	prev := []audit.Finding{
		{
			Service:    "ec2",
			ResourceID: "i-111",
			Check:      "imds",
			Status:     "PASS",
			RiskLevel:  "MINIMAL",
			Region:     "eu-west-1",
		},
	}
	curr := []audit.Finding{
		{
			Service:    "ec2",
			ResourceID: "i-111",
			Check:      "imds",
			Status:     "PASS",
			RiskLevel:  "MINIMAL",
			Region:     "eu-west-1",
		},
	}

	d := ComputeDiff(prev, curr)

	if len(d.New) != 0 || len(d.Resolved) != 0 || len(d.Ongoing) != 0 {
		t.Errorf(
			"PASS findings should be ignored: new=%d resolved=%d ongoing=%d",
			len(d.New),
			len(d.Resolved),
			len(d.Ongoing),
		)
	}
}
