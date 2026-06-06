// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
	"github.com/optiqor/kerno/internal/doctor"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestOOMKillCapturedFromConstrainedCgroup(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	loader := bpf.NewOOMTrackLoader(logger)
	closer, err := loader.Load()
	if err != nil {
		t.Skipf("skip OOM integration test: load oom_track: %v", err)
	}
	t.Cleanup(func() {
		_ = closer.Close()
	})

	oomCollector := collector.NewOOMCollector(logger, loader)
	if err := oomCollector.Start(ctx); err != nil {
		t.Fatalf("start oom collector: %v", err)
	}
	t.Cleanup(oomCollector.Stop)

	victim, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "docker.io/library/python:3.12-alpine",
			Cmd: []string{
				"sh",
				"-c",
				"ulimit -v 65536; python3 -c 'chunks=[]\nwhile True:\n chunks.append(bytearray(8*1024*1024))'",
			},
			WaitingFor:      wait.ForExit().WithExitTimeout(45 * time.Second),
			AlwaysPullImage: false,
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start oom victim container: %v", err)
	}

	t.Cleanup(func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer terminateCancel()
		_ = victim.Terminate(terminateCtx)
	})

	var snap *collector.OOMSnapshot
	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		got := oomCollector.Snapshot()

		var ok bool
		snap, ok = got.(*collector.OOMSnapshot)
		if ok && snap.Count > 0 {
			break
		}

		time.Sleep(250 * time.Millisecond)
	}

	if snap == nil || snap.Count == 0 {
		t.Fatalf("expected oom collector to capture at least one event")
	}

	var captured *collector.OOMEventEntry
	for i := range snap.Events {
		event := &snap.Events[i]
		if strings.Contains(event.Comm, "python") || event.OOMScore != 0 {
			captured = event
			break
		}
	}

	if captured == nil {
		t.Fatalf("expected captured OOM event for victim process, got %#v", snap.Events)
	}
	if captured.PID == 0 {
		t.Fatalf("expected captured OOM event PID to be set, got %#v", captured)
	}
	if captured.Comm == "" {
		t.Fatalf("expected captured OOM event comm to be set, got %#v", captured)
	}

	signals := &collector.Signals{
		Timestamp: time.Now(),
		Duration:  30 * time.Second,
		OOM:       snap,
	}

	findings := doctor.Evaluate(signals, config.Default().Doctor.Thresholds)

	for _, finding := range findings {
		if finding.Rule == "oom_kill_occurred" && finding.Severity == doctor.SeverityCritical {
			return
		}
	}

	t.Fatalf("expected critical oom_kill_occurred finding, got %#v", findings)
}
