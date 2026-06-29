// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/chaos"
)

func TestChaosIntegration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping integration test: Linux only")
	}
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges (eBPF)")
	}

	// Verify eBPF is functional by loading OOM tracker (same as oom_kill_test.go)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	loader := bpf.NewOOMTrackLoader(logger)
	closer, err := loader.Load()
	if err != nil {
		t.Skipf("Skipping integration test: eBPF not functional: %v", err)
	}
	closer.Close()

	// Build the kerno binary with 'ebpf' tag
	tmpDir, err := os.MkdirTemp("", "kerno-integration-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kernoPath := filepath.Join(tmpDir, "kerno")
	buildCmd := exec.Command("go", "build", "-tags", "ebpf", "-o", kernoPath, "github.com/optiqor/kerno/cmd/kerno")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build kerno binary: %v\nOutput: %s", err, string(out))
	}

	// Write a test-tuned configuration file with lower thresholds to ensure quick and reliable rule firing.
	configPath := filepath.Join(tmpDir, "integration-config.yaml")
	configContent := `
log_level: info
log_format: text

doctor:
  duration: 8s
  thresholds:
    disk_p99_warning_ns:   2000000     # 2ms
    disk_p99_critical_ns: 20000000    # 20ms
    sched_delay_warning_ns:   100000  # 100us
    sched_delay_critical_ns: 5000000  # 5ms
    fd_growth_per_sec: 5
    syscall_p99_warning_ns:  100000000   # 100ms
    syscall_p99_critical_ns: 500000000   # 500ms
    oom_memory_pct: 90.0

prometheus:
  enabled: false

ai:
  enabled: false
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	scenarios := chaos.List()
	for _, s := range scenarios {
		s := s // pin
		if s.Name() == "cascade" {
			continue
		}

		t.Run(s.Name(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()

			if s.Name() == "tcp-loss" {
				// Apply 30% packet loss to loopback interface for tcp-loss scenario
				tcCmd := exec.Command("tc", "qdisc", "add", "dev", "lo", "root", "netem", "loss", "30%")
				if err := tcCmd.Run(); err != nil {
					t.Skipf("skipping tcp-loss: failed to apply packet loss via tc: %v", err)
				}
				defer func() {
					_ = exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run()
				}()
			}

			// Start chaos induction in background
			chaosCmd := exec.CommandContext(ctx, kernoPath, "chaos", "--induce", s.Name(), "--duration", "12s", "--intensity", "high", "--yes")
			if s.Name() == "cgroup-memory" {
				chaosCmd.Env = append(os.Environ(), "KERNO_CGROUP_ROOT=/tmp/kerno-chaos-cgroup")
			} else {
				chaosCmd.Env = os.Environ()
			}

			var chaosBuf bytes.Buffer
			chaosCmd.Stdout = &chaosBuf
			chaosCmd.Stderr = &chaosBuf

			if err := chaosCmd.Start(); err != nil {
				t.Fatalf("failed to start chaos scenario %s: %v", s.Name(), err)
			}

			defer func() {
				if chaosCmd.Process != nil {
					_ = chaosCmd.Process.Kill()
				}
				_ = chaosCmd.Wait()
				_ = os.RemoveAll("/tmp/kerno-chaos-cgroup")
			}()

			// Wait for chaos to start generating signals
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				t.Fatalf("timeout waiting for chaos to start")
			}

			// Run doctor to collect signals and evaluate rules
			doctorCmd := exec.CommandContext(ctx, kernoPath, "--config", configPath, "doctor", "--duration", "6s", "--output", "json")
			if s.Name() == "cgroup-memory" {
				doctorCmd.Env = append(os.Environ(), "KERNO_CGROUP_ROOT=/tmp/kerno-chaos-cgroup")
			} else {
				doctorCmd.Env = os.Environ()
			}

			doctorOut, err := doctorCmd.CombinedOutput()
			if err != nil {
				t.Fatalf("failed to run doctor: %v\nOutput: %s\nChaos Output: %s", err, string(doctorOut), chaosBuf.String())
			}

			var report struct {
				Findings []struct {
					Rule     string `json:"rule"`
					Severity string `json:"severity"`
				} `json:"findings"`
			}
			if err := json.Unmarshal(doctorOut, &report); err != nil {
				t.Fatalf("failed to parse doctor JSON output: %v\nOutput: %s", err, string(doctorOut))
			}

			// Assert that the scenario's PairedRule is present in findings
			expectedRule := s.PairedRule()
			found := false
			for _, f := range report.Findings {
				if f.Rule == expectedRule {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("expected rule %q to fire for scenario %q, but not found in findings: %+v\nDoctor Output: %s\nChaos Output: %s",
					expectedRule, s.Name(), report.Findings, string(doctorOut), chaosBuf.String())
			}
		})
	}
}
