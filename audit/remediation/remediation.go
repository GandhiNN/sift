package remediation

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sift/audit"
)

//go:embed remediations.json
var embeddedData embed.FS

type template struct {
	Action     string `json:"action"`
	Command    string `json:"command"`
	Confidence string `json:"confidence"`
	ActionRisk string `json:"action_risk"`
}

// module -> service -> check -> template
var table map[string]map[string]map[string]template

func init() {
	table = load()
}

func load() map[string]map[string]map[string]template {
	// Try user override
	home, err := os.UserHomeDir()
	if err == nil {
		override := filepath.Join(home, ".sift", "remediations.json")
		if data, err := os.ReadFile(override); err == nil {
			var t map[string]map[string]map[string]template
			if json.Unmarshal(data, &t) == nil {
				return t
			}
		}
	}

	// Fall back to embedded
	data, err := embeddedData.ReadFile("remediations.json")
	if err != nil {
		panic(fmt.Sprintf("failed to read embedded remediations: %v", err))
	}
	var t map[string]map[string]map[string]template
	if err := json.Unmarshal(data, &t); err != nil {
		panic(fmt.Sprintf("failed to parse embedded remediations: %v", err))
	}
	return t
}

// Recommend returns a Remediation for the given module/service/check, or nil if none defined.
func Recommend(module, service, check, resourceID, evidence string) *audit.Remediation {
	mod, ok := table[module]
	if !ok {
		return nil
	}
	svc, ok := mod[service]
	if !ok {
		return nil
	}
	tmpl, ok := svc[check]
	if !ok {
		return nil
	}

	cmd := tmpl.Command
	cmd = strings.ReplaceAll(cmd, "{{.ResourceID}}", resourceID)

	return &audit.Remediation{
		Action:     tmpl.Action,
		Command:    cmd,
		Evidence:   evidence,
		Confidence: tmpl.Confidence,
		ActionRisk: tmpl.ActionRisk,
	}
}
