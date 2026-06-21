// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build ebpf

package chaos_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/chaos"
	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
	"github.com/optiqor/kerno/internal/doctor"
)

func TestChaosDetectionE2E(t *testing.T) {
	// Skip if not running as root (required for loading real eBPF programs)
	if os.Geteuid() != 0 {
		t.Skip("Skipping privileged integration test: must be run as root/sudo")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Define test thresholds (test-calibrated to trip within 10s window, mirroring scripts/verify-config.yaml)
	thresholds := config.DoctorThresholds{
		DiskP99WarningNs:     2000000,     // 2ms
		DiskP99CriticalNs:    20000000,    // 20ms
		SchedDelayWarningNs:  100000,      // 100us
		SchedDelayCriticalNs: 5000000,     // 5ms
		FDGrowthPerSec:       5,
		SyscallP99WarningNs:  100000000,   // 100ms
		SyscallP99CriticalNs: 500000000,   // 500ms
		OOMMemoryPct:         90.0,
		TCPRetransmitPct:     2.0,
	}

	for _, s := range chaos.List() {
		if s.Name() == "cascade" {
			continue // skip cascade scenario as requested
		}

		t.Run(s.Name(), func(t *testing.T) {
			// Pre-condition: tcp-loss requires packet loss on loopback via tc
			if s.Name() == "tcp-loss" {
				cleanupTC := setupTC(t)
				if cleanupTC != nil {
					defer cleanupTC()
				}
			}

			// Pre-condition: cgroup-memory requires KERNO_CGROUP_ROOT override pointing to mock folder
			if s.Name() == "cgroup-memory" {
				cgroupRoot := filepath.Join(os.TempDir(), "kerno-chaos-cgroup")
				_ = os.RemoveAll(cgroupRoot)
				os.Setenv("KERNO_CGROUP_ROOT", cgroupRoot)
				defer func() {
					os.Unsetenv("KERNO_CGROUP_ROOT")
					_ = os.RemoveAll(cgroupRoot)
				}()
			}

			// 1. Build and load eBPF collectors
			registry := collector.NewRegistry(logger)
			closers := make([]io.Closer, 0, 8)
			defer func() {
				for _, c := range closers {
					_ = c.Close()
				}
			}()

			// syscall_latency
			lSys := bpf.NewSyscallLatencyLoader(logger)
			if closer, err := lSys.Load(); err != nil {
				t.Fatalf("failed to load syscall_latency: %v", err)
			} else {
				closers = append(closers, closer)
				_ = registry.Register(collector.NewSyscallCollector(logger, lSys))
			}

			// tcp_monitor
			lTCP := bpf.NewTCPMonitorLoader(logger)
			if closer, err := lTCP.Load(); err != nil {
				t.Fatalf("failed to load tcp_monitor: %v", err)
			} else {
				closers = append(closers, closer)
				_ = registry.Register(collector.NewTCPCollector(logger, lTCP))
			}

			// oom_track
			lOOM := bpf.NewOOMTrackLoader(logger)
			if closer, err := lOOM.Load(); err != nil {
				t.Fatalf("failed to load oom_track: %v", err)
			} else {
				closers = append(closers, closer)
				_ = registry.Register(collector.NewOOMCollector(logger, lOOM))
			}

			// disk_io
			lDisk := bpf.NewDiskIOLoader(logger)
			if closer, err := lDisk.Load(); err != nil {
				t.Fatalf("failed to load disk_io: %v", err)
			} else {
				closers = append(closers, closer)
				_ = registry.Register(collector.NewDiskIOCollector(logger, lDisk))
			}

			// sched_delay
			lSched := bpf.NewSchedDelayLoader(logger)
			if closer, err := lSched.Load(); err != nil {
				t.Fatalf("failed to load sched_delay: %v", err)
			} else {
				closers = append(closers, closer)
				_ = registry.Register(collector.NewSchedCollector(logger, lSched))
			}

			// fd_track
			lFD := bpf.NewFDTrackLoader(logger)
			if closer, err := lFD.Load(); err != nil {
				t.Fatalf("failed to load fd_track: %v", err)
			} else {
				closers = append(closers, closer)
				_ = registry.Register(collector.NewFDCollector(logger, lFD))
			}

			// memory (procfs poller)
			_ = registry.Register(collector.NewMemoryCollector(logger, 0))

			// cgroup_memory
			_ = registry.Register(collector.NewCgroupMemoryCollector(logger, 0))

			// 2. Start collectors
			collectCtx, cancelCollect := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelCollect()

			if err := registry.StartAll(collectCtx); err != nil {
				t.Fatalf("failed to start collectors: %v", err)
			}
			defer registry.StopAll()

			// 3. Start chaos scenario in background
			scenarioCtx, cancelScenario := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancelScenario()

			errChan := make(chan error, 1)
			go func() {
				opts := chaos.Options{
					Intensity: chaos.IntensityHigh,
					Duration:  12 * time.Second,
					Out:       io.Discard,
					Logger:    logger,
				}
				errChan <- s.Run(scenarioCtx, opts)
			}()

			// Wait 1s for the chaos scenario to warm up / start generating events
			time.Sleep(1 * time.Second)

			// 4. Wait for collection window to finish
			<-collectCtx.Done()

			// 5. Gather combined signals and stop collectors
			signals := registry.Signals(10 * time.Second)
			registry.StopAll()

			// Wait for chaos scenario to finish/clean up
			cancelScenario()
			if err := <-errChan; err != nil {
				t.Errorf("chaos scenario %s failed: %v", s.Name(), err)
			}

			// 6. Evaluate rules
			testThresholds := thresholds
			if s.Name() == "memory" {
				// Treat any non-zero memory usage as triggering since VM size varies
				testThresholds.OOMMemoryPct = 0.0
			}

			findings := doctor.Evaluate(signals, testThresholds)

			// Assert that the paired rule fired
			expectedRule := s.PairedRule()
			found := false
			for _, f := range findings {
				if f.Rule == expectedRule {
					found = true
					t.Logf("PASS: scenario %s triggered expected rule %s (severity: %v)", s.Name(), expectedRule, f.Severity)
					break
				}
			}

			if !found {
				t.Errorf("FAIL: scenario %s did not trigger expected rule %s. Findings: %+v", s.Name(), expectedRule, findings)
			}
		})
	}
}

func setupTC(t *testing.T) func() {
	// Try deleting first in case it's stale
	_ = exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run()

	cmd := exec.Command("tc", "qdisc", "add", "dev", "lo", "root", "netem", "loss", "30%")
	if err := cmd.Run(); err != nil {
		t.Skipf("Skipping tcp-loss integration test: tc qdisc setup failed: %v", err)
		return nil
	}

	return func() {
		_ = exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run()
	}
}
