package audit

type Resource struct {
	Region     string            `json:"region,omitempty"`
	Service    string            `json:"service"`
	ResourceID string            `json:"resource_id"`
	Type       string            `json:"type"`
	Tags       map[string]string `json:"tags,omitempty"`
	Properties map[string]string `json:"properties"`
}
