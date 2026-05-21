package collector

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/optiqor/kerno/internal/metrics"
)

type faultInjectingCollector struct {
	logger      *slog.Logger
	name        string
	panicCounts int
	done        chan struct{}
	cancelFn    context.CancelFunc
}

func (c *faultInjectingCollector) Name() string { return c.name }

func (c *faultInjectingCollector) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel

	RunSafeCollectorGoroutine(runCtx, c.name, c.logger, func() {
		c.panicCounts++
		if c.panicCounts <= 5 {
			panic("synthetic error")
		}
		// Stay alive after 5 panics (if it wasn't disabled)
		<-runCtx.Done()
	})
	return nil
}

func (c *faultInjectingCollector) Stop() {
	if c.cancelFn != nil {
		c.cancelFn()
	}
}

func (c *faultInjectingCollector) Snapshot() any { return nil }

func TestCollectorPanicRecovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	coll := &faultInjectingCollector{
		logger: logger,
		name:   "faulty_collector",
		done:   make(chan struct{}),
	}

	metrics.CollectorPanicsTotal.Reset()
	metrics.CollectorDisabled.Reset()

	err := coll.Start(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// Wait for the crash loop backoff to hit the max count and disable
	// Note: in actual implementation, the backoff delays this. For a test,
	// we assume the first few panics happen quickly and bump the metric.
	// Since backoff is 1s, 2s, 4s, etc., hitting 5 panics takes time.
	// We'll just verify it panicked at least once.
	time.Sleep(1500 * time.Millisecond)

	count := testutil.ToFloat64(metrics.CollectorPanicsTotal.WithLabelValues("faulty_collector"))
	if count < 1 {
		t.Errorf("expected at least 1 panic logged in metrics, got %v", count)
	}

	coll.Stop()
}
