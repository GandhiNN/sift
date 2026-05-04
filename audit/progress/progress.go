package progress

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

type ctxKey struct{}

// WithSubProgress returns a context that controls whether sub-service progress bars are visible.
func WithSubProgress(ctx context.Context, show bool) context.Context {
	return context.WithValue(ctx, ctxKey{}, show)
}

func showSub(ctx context.Context) bool {
	v, ok := ctx.Value(ctxKey{}).(bool)
	return !ok || v // default true if not set
}

// OrchestratorBar wraps a progressbar that prints a new line after each tick.
type OrchestratorBar struct {
	bar   *progressbar.ProgressBar
	mu    sync.Mutex
	label string
}

// NewOrchestratorBar creates a fixed-width bar for orchestrators that stays on one line.
func NewOrchestratorBar(total int64, desc string) *OrchestratorBar {
	bar := progressbar.NewOptions64(
		total,
		progressbar.OptionSetDescription(desc),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(50),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionSetRenderBlankState(true),
	)
	return &OrchestratorBar{bar: bar, label: desc}
}

// NewBar creates a determinate progress bar. Hidden when sub-progress is suppressed.
func NewBar(ctx context.Context, total int64, desc string) *progressbar.ProgressBar {
	if !showSub(ctx) {
		return progressbar.NewOptions64(total, progressbar.OptionSetWriter(io.Discard))
	}
	return progressbar.Default(total, desc)
}

func (o *OrchestratorBar) Done(service string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.bar.Describe(fmt.Sprintf("%s [done: %-10s]", o.label, service))
	o.bar.Add(1)
	fmt.Fprint(os.Stderr, "\n")
}

// NewSpinner creates an indeterminate spinner. Hidden when sub-progress is suppressed.
func NewSpinner(ctx context.Context, desc string) *progressbar.ProgressBar {
	if !showSub(ctx) {
		return progressbar.NewOptions(-1, progressbar.OptionSetWriter(io.Discard))
	}
	return progressbar.NewOptions(-1,
		progressbar.OptionSetDescription(desc),
		progressbar.OptionSpinnerType(14),
	)
}
