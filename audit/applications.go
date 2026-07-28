package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// AppConfig defines the application matching configuration.
type AppConfig struct {
	Applications []AppEntry `json:"applications"`
	Default      string     `json:"default"`
}

// AppEntry defines one application with its name and matching patterns.
type AppEntry struct {
	Name     string   `json:"name"`
	Patterns []string `json:"patterns"`
}

// AppMatcher performs fuzzy matching of resource IDs and Name tags to applications.
type AppMatcher struct {
	apps     []AppEntry
	fallback string
}

// LoadAppMatcher loads application config from ~/.sift/applications.json
// Returns nil if the file does not exist
func LoadAppMatcher() *AppMatcher {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	path := filepath.Join(home, ".sift", "applications.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	fallback := cfg.Default
	if fallback == "" {
		fallback = "Unknown"
	}
	return &AppMatcher{apps: cfg.Applications, fallback: fallback}
}

// Match returns the application name for a given resource ID and Name tag.
// It checks the Name tag first (more descriptive), then the resource ID.
func (m *AppMatcher) Match(resourceID string, tags map[string]string) string {
	if m == nil {
		return ""
	}

	nameTag := ""
	if tags != nil {
		nameTag = tags["Name"]
	}

	// Check Name tag first, then resource ID
	candidates := []string{nameTag, resourceID}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		lower := strings.ToLower(candidate)
		for _, app := range m.apps {
			for _, pattern := range app.Patterns {
				if strings.Contains(lower, strings.ToLower(pattern)) {
					return app.Name
				}
			}
		}
	}

	return m.fallback
}

// ApplyApplications enriches findings with application names based on matching.
func ApplyApplications(findings []Finding, matcher *AppMatcher) {
	if matcher == nil {
		return
	}
	for i := range findings {
		findings[i].Application = matcher.Match(findings[i].ResourceID, findings[i].Tags)
	}
}
