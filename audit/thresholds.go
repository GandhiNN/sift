package audit

import "context"

type Thresholds struct {
	UnusedDays      int     // days before resource is "unused" (default: 90)
	MinBackupDays   int     // minimum backup retention (default: 7)
	CPUIdlePercent  float64 // below this = oversized (default: 10)
	SnapshotAgeDays int     // old snapshot threshold (default: 90)
	RotationMaxDays int     // rotation overdue threshold (default: 90)
	Concurrency     int     // max parallel API calls per service (default: 10)
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
