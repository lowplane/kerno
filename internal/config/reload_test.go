// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

// TestConfigDiff verifies that every config field change is correctly
// classified by diff() into the Applied or RestartRequired bucket.
//
// Table-driven design: adding a new config field without updating diff()
// will NOT automatically fail this test, but the template comment below
// ("ADD NEW FIELD CASES HERE") makes the gap visible during code review.
// The reviewer's suggested table structure is followed exactly.
func TestConfigDiff(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		mutate        func(c *Config)
		expectApplied []string // substrings that must appear in result.Applied
		expectRestart bool     // true → at least one entry in RestartRequired expected
	}{
		// Log level / format (always reloadable)
		{
			name:          "log_level changes",
			mutate:        func(c *Config) { c.LogLevel = "debug" },
			expectApplied: []string{"log_level"},
		},
		{
			name:          "log_format changes",
			mutate:        func(c *Config) { c.LogFormat = "json" },
			expectApplied: []string{"log_format"},
		},

		// Prometheus (hot-reloadable)
		{
			name:          "prometheus.addr changes",
			mutate:        func(c *Config) { c.Prometheus.Addr = ":9091" },
			expectApplied: []string{"prometheus.addr"},
		},
		{
			name:          "prometheus.enabled toggled",
			mutate:        func(c *Config) { c.Prometheus.Enabled = !c.Prometheus.Enabled },
			expectApplied: []string{"prometheus.enabled"},
		},

		// Doctor thresholds (restart required — daemon has no engine consumer)
		{
			name: "doctor.thresholds updated",
			mutate: func(c *Config) {
				c.Doctor.Thresholds.OOMMemoryPct = 99.0
			},
			expectRestart: true,
		},
		{
			name: "doctor.duration changes",
			mutate: func(c *Config) {
				c.Doctor.Duration = 5 * time.Minute
			},
			expectRestart: true,
		},

		// AI config (restart required)
		{
			name: "ai config updated",
			mutate: func(c *Config) {
				c.AI.Enabled = !c.AI.Enabled
			},
			expectRestart: true,
		},

		// Dashboard config (restart required)
		{
			name: "dashboard config updated",
			mutate: func(c *Config) {
				c.Dashboard.Addr = ":3001"
			},
			expectRestart: true,
		},

		// Kubernetes config (restart required)
		{
			name: "kubernetes config updated",
			mutate: func(c *Config) {
				c.Kubernetes.Enabled = !c.Kubernetes.Enabled
			},
			expectRestart: true,
		},

		//  Collector toggles (RESTART REQUIRED)
		// Each collector is tied to a BPF program that has already been loaded;
		// toggling it at runtime would require unloading / reloading the program,
		// which is intentionally not supported. diff() must put these in
		// RestartRequired, not Applied.
		{
			name: "collectors.syscall_latency toggle",
			mutate: func(c *Config) {
				c.Collectors.SyscallLatency = !c.Collectors.SyscallLatency
			},
			expectRestart: true,
		},
		{
			name: "collectors.tcp_monitor toggle",
			mutate: func(c *Config) {
				c.Collectors.TCPMonitor = !c.Collectors.TCPMonitor
			},
			expectRestart: true,
		},
		{
			name: "collectors.oom_track toggle",
			mutate: func(c *Config) {
				c.Collectors.OOMTrack = !c.Collectors.OOMTrack
			},
			expectRestart: true,
		},
		{
			name: "collectors.disk_io toggle",
			mutate: func(c *Config) {
				c.Collectors.DiskIO = !c.Collectors.DiskIO
			},
			expectRestart: true,
		},
		{
			name: "collectors.sched_delay toggle",
			mutate: func(c *Config) {
				c.Collectors.SchedDelay = !c.Collectors.SchedDelay
			},
			expectRestart: true,
		},
		{
			name: "collectors.fd_track toggle",
			mutate: func(c *Config) {
				c.Collectors.FDTrack = !c.Collectors.FDTrack
			},
			expectRestart: true,
		},
		{
			name: "collectors.file_audit toggle",
			mutate: func(c *Config) {
				c.Collectors.FileAudit = !c.Collectors.FileAudit
			},
			expectRestart: true,
		},

		//  Sanity: no changes
		{
			name:   "no changes — both lists empty",
			mutate: func(_ *Config) {}, // identity mutation
		},

		//  Sanity: multiple reloadable changes
		{
			name: "multiple reloadable changes",
			mutate: func(c *Config) {
				c.LogLevel = "warn"
				c.Prometheus.Addr = ":9091"
			},
			expectApplied: []string{"log_level", "prometheus.addr"},
		},

		//  Sanity: mixed reloadable + restart-required
		{
			name: "reloadable + restart-required mix",
			mutate: func(c *Config) {
				c.LogLevel = "warn"
				c.Collectors.SyscallLatency = !c.Collectors.SyscallLatency
			},
			expectApplied: []string{"log_level"},
			expectRestart: true,
		},

		// ADD NEW FIELD CASES HERE when adding fields to Config.
	}

	for _, tc := range cases {
		// Fix: removed `tc := tc` loop-variable copy — redundant in Go 1.22+
		// where loop variables are re-bound per iteration automatically.
		// The copyloopvar golangci-lint check flags the old pattern.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			old := Default()
			next := Default()
			tc.mutate(next)

			result := diff(old, next)

			//  Applied assertions
			if len(tc.expectApplied) > 0 {
				if len(result.Applied) == 0 {
					t.Fatalf("expected Applied changes but got none")
				}
				for _, want := range tc.expectApplied {
					found := false
					for _, got := range result.Applied {
						if strings.Contains(got, want) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected Applied to contain %q\n  got: %v", want, result.Applied)
					}
				}
			}

			//  No unexpected Applied entries
			if len(tc.expectApplied) == 0 && !tc.expectRestart && len(result.Applied) > 0 {
				t.Errorf("expected no Applied changes but got: %v", result.Applied)
			}

			// RestartRequired assertions
			if tc.expectRestart && len(result.RestartRequired) == 0 {
				t.Errorf("expected RestartRequired changes but got none")
			}
			if !tc.expectRestart && len(result.RestartRequired) > 0 {
				t.Errorf("expected no RestartRequired changes but got: %v", result.RestartRequired)
			}
		})
	}
}

// TestReloadResultString checks the human-readable summary format that is
// logged after every successful SIGHUP reload.
func TestReloadResultString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		r    ReloadResult
		want string
	}{
		{
			r:    ReloadResult{},
			want: "config reloaded; 0 changes applied; 0 changes require restart",
		},
		{
			r:    ReloadResult{Applied: []string{"log_level", "prometheus.addr"}},
			want: "config reloaded; 2 changes applied; 0 changes require restart",
		},
		{
			r: ReloadResult{
				Applied:         []string{"log_level"},
				RestartRequired: []string{"collectors.syscall_latency: true → false"},
			},
			want: "config reloaded; 1 changes applied; 1 changes require restart",
		},
	}

	for _, tc := range cases {
		got := tc.r.String()
		if got != tc.want {
			t.Errorf("ReloadResult.String()\n  want: %q\n   got: %q", tc.want, got)
		}
	}
}
