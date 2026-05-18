package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

type Thresholds struct {
	UnusedDays      int                           `json:"unused_days"`
	MinBackupDays   int                           `json:"min_backup_days"`
	CPUIdlePercent  float64                       `json:"cpu_idle_percent"`
	SnapshotAgeDays int                           `json:"snapshot_age_days"`
	RotationMaxDays int                           `json:"rotation_max_days"`
	Concurrency     int                           `json:"concurrency"`
	Services        map[string]map[string]float64 `json:"services,omitempty"`
}

func (t Thresholds) GetFloat(service, key string, fallback float64) float64 {
	if svc, ok := t.Services[service]; ok {
		if v, ok := svc[key]; ok {
			return v
		}
	}
	return fallback
}

func (t Thresholds) GetInt(service, key string, fallback int) int {
	return int(t.GetFloat(service, key, float64(fallback)))
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		UnusedDays:      90,
		MinBackupDays:   7,
		CPUIdlePercent:  10,
		SnapshotAgeDays: 90,
		RotationMaxDays: 90,
		Concurrency:     10,
	}
}

func LoadThresholds() Thresholds {
	t := DefaultThresholds()
	home, err := os.UserHomeDir()
	if err != nil {
		return t
	}
	data, err := os.ReadFile(filepath.Join(home, ".sift", "config.json"))
	if err != nil {
		return t
	}
	var cfg configFile
	if json.Unmarshal(data, &cfg) != nil || cfg.Thresholds == nil {
		return t
	}

	if g := cfg.Thresholds.Global; g != nil {
		if v, ok := (*g)["unused_days"]; ok {
			t.UnusedDays = int(v)
		}
		if v, ok := (*g)["min_backup_days"]; ok {
			t.MinBackupDays = int(v)
		}
		if v, ok := (*g)["cpu_idle_percent"]; ok {
			t.CPUIdlePercent = v
		}
		if v, ok := (*g)["snapshot_age_days"]; ok {
			t.SnapshotAgeDays = int(v)
		}
		if v, ok := (*g)["rotation_max_days"]; ok {
			t.RotationMaxDays = int(v)
		}
		if v, ok := (*g)["concurrency"]; ok {
			t.Concurrency = int(v)
		}
	}

	t.Services = cfg.Thresholds.Services
	return t
}

type configFile struct {
	Thresholds *configThresholds `json:"thresholds"`
}

type configThresholds struct {
	Global   *map[string]float64           `json:"global,omitempty"`
	Services map[string]map[string]float64 `json:"services,omitempty"`
}

type thresholdsKey struct{}

func WithThresholds(ctx context.Context, t Thresholds) context.Context {
	return context.WithValue(ctx, thresholdsKey{}, t)
}

func GetThresholds(ctx context.Context) Thresholds {
	if t, ok := ctx.Value(thresholdsKey{}).(Thresholds); ok {
		return t
	}
	return DefaultThresholds()
}
