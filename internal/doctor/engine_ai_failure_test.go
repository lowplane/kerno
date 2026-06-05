package doctor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
)

type failingAnalyzer struct{}

func (failingAnalyzer) Analyze(_ context.Context, _ AnalysisRequest) (*AnalysisResponse, error) {
	return nil, errors.New("provider failed")
}

func TestEngineDiagnoseContinuesWhenAnalyzerFails(t *testing.T) {
	signals := &collector.Signals{
		Timestamp: time.Now(),
		Duration:  30 * time.Second,
		Host: collector.HostInfo{
			KernelVer: "test-kernel",
		},
		DiskIO: &collector.DiskIOSnapshot{
			SyncLatency: collector.Percentiles{
				P99: 300 * time.Millisecond,
			},
			TotalSyncs: 500,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewEngine(config.Default().Doctor.Thresholds, failingAnalyzer{}, logger)

	report, err := engine.Diagnose(context.Background(), signals)
	if err != nil {
		t.Fatalf("Diagnose returned error: %v", err)
	}

	if report == nil {
		t.Fatal("expected report, got nil")
	}

	if len(report.Findings) == 0 {
		t.Fatal("expected deterministic findings to remain when AI fails")
	}

	foundDiskFinding := false
	for _, finding := range report.Findings {
		if finding.Rule == "disk_io_bottleneck" {
			foundDiskFinding = true
			break
		}
	}

	if !foundDiskFinding {
		t.Fatalf("expected disk_io_bottleneck deterministic finding, got: %#v", report.Findings)
	}
}
