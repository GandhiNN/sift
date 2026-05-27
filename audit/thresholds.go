package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

type Thresholds struct {
	Concurrency int                           `json:"concurrency"`
	Services    map[string]map[string]float64 `json:"services,omitempty"`
}

type configFile struct {
	Thresholds *configThresholds `json:"thresholds"`
}

type configThresholds struct {
	Concurrency int                           `json:"concurrency,omitempty"`
	Services    map[string]map[string]float64 `json:"services,omitempty"`
}

type thresholdsKey struct{}

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
		Concurrency: 10,
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

	if cfg.Thresholds.Concurrency > 0 {
		t.Concurrency = cfg.Thresholds.Concurrency
	}

	t.Services = cfg.Thresholds.Services
	return t
}

func WithThresholds(ctx context.Context, t Thresholds) context.Context {
	return context.WithValue(ctx, thresholdsKey{}, t)
}

func GetThresholds(ctx context.Context) Thresholds {
	if t, ok := ctx.Value(thresholdsKey{}).(Thresholds); ok {
		return t
	}
	return DefaultThresholds()
}
