package audit

type Finding struct {
	Region     string `json:"region,omitempty"`
	Service    string `json:"service"`
	ResourceID string `json:"resource_id"`
	Check      string `json:"check"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	RiskLevel  string `json:"risk_level"`
}
