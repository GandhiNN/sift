package audit

import "fmt"

type Finding struct {
	Region               string            `json:"region,omitempty"`
	Service              string            `json:"service"`
	ResourceID           string            `json:"resource_id"`
	Tags                 map[string]string `json:"tags,omitempty"`
	Check                string            `json:"check"`
	Status               string            `json:"status"`
	Detail               string            `json:"detail"`
	RiskLevel            string            `json:"risk_level"`
	EstimatedMonthlyCost float64           `json:"estimated_monthly_cost,omitempty"`
	Remediation          string            `json:"remediation,omitempty"`
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
