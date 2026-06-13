package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type Remediation struct {
	Action     string `json:"action"`
	Command    string `json:"command,omitempty"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"`
	ActionRisk string `json:"action_risk"`
}

type Finding struct {
	ID                   string            `json:"id"`
	Region               string            `json:"region,omitempty"`
	Service              string            `json:"service"`
	ResourceID           string            `json:"resource_id"`
	Tags                 map[string]string `json:"tags,omitempty"`
	Check                string            `json:"check"`
	Status               string            `json:"status"`
	Detail               string            `json:"detail"`
	RiskLevel            string            `json:"risk_level"`
	EstimatedMonthlyCost float64           `json:"estimated_monthly_cost,omitempty"`
	Remediation          *Remediation      `json:"remediation,omitempty"`
}

// ComputeID sets the finding ID as a short hash of service+resource+check
func (f *Finding) ComputeID() {
	h := sha256.Sum256([]byte(f.Service + "/" + f.ResourceID + "/" + f.Check))
	f.ID = hex.EncodeToString(h[:8])
}

func ErrorFinding(service, resourceID, check string, err error) Finding {
	return Finding{
		Service:    service,
		ResourceID: resourceID,
		Check:      check,
		Status:     "ERROR",
		Detail:     fmt.Sprintf("audit failed: %v", err),
		RiskLevel:  "UNKNOWN",
	}
}

type checksKey struct{}

func WithChecks(ctx context.Context, checks []string) context.Context {
	return context.WithValue(ctx, checksKey{}, checks)
}

func GetChecks(ctx context.Context) []string {
	if v, ok := ctx.Value(checksKey{}).([]string); ok {
		return v
	}
	return nil
}

type servicesKey struct{}

func WithServices(ctx context.Context, services []string) context.Context {
	return context.WithValue(ctx, servicesKey{}, services)
}

func GetServices(ctx context.Context) []string {
	if v, ok := ctx.Value(servicesKey{}).([]string); ok {
		return v
	}
	return nil
}
