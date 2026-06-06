// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"testing"
	"time"
)

// TestNewViperEnvOverrides verifies that KERNO_* environment variables flow
// through to the typed config. This guards against the regression in #112,
// where AutomaticEnv had no registered keys and silently dropped every env var
// except the three bound flags.
func TestNewViperEnvOverrides(t *testing.T) {
	// Covers a string flag key (per the issue), plus keys that were broken
	// before the fix across every value type: string, bool, and duration.
	t.Setenv("KERNO_LOG_LEVEL", "debug")
	t.Setenv("KERNO_AI_API_KEY", "secret")
	t.Setenv("KERNO_AI_ENABLED", "true")
	t.Setenv("KERNO_PROMETHEUS_ADDR", ":1234")
	t.Setenv("KERNO_DOCTOR_DURATION", "45s")

	cfg := Default()
	if err := NewViper().Unmarshal(cfg); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q (KERNO_LOG_LEVEL)", cfg.LogLevel, "debug")
	}
	if cfg.AI.APIKey != "secret" {
		t.Errorf("AI.APIKey = %q, want %q (KERNO_AI_API_KEY)", cfg.AI.APIKey, "secret")
	}
	if !cfg.AI.Enabled {
		t.Error("AI.Enabled = false, want true (KERNO_AI_ENABLED)")
	}
	if cfg.Prometheus.Addr != ":1234" {
		t.Errorf("Prometheus.Addr = %q, want %q (KERNO_PROMETHEUS_ADDR)", cfg.Prometheus.Addr, ":1234")
	}
	if cfg.Doctor.Duration != 45*time.Second {
		t.Errorf("Doctor.Duration = %s, want 45s (KERNO_DOCTOR_DURATION)", cfg.Doctor.Duration)
	}
}

// TestNewViperDefaultsPreserved ensures that registering keys as viper defaults
// does not clobber the values from Default() when no env var is set.
func TestNewViperDefaultsPreserved(t *testing.T) {
	cfg := Default()
	if err := NewViper().Unmarshal(cfg); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	want := Default()
	if cfg.LogLevel != want.LogLevel {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, want.LogLevel)
	}
	if cfg.Prometheus.Addr != want.Prometheus.Addr {
		t.Errorf("Prometheus.Addr = %q, want %q", cfg.Prometheus.Addr, want.Prometheus.Addr)
	}
	if cfg.Doctor.Duration != want.Doctor.Duration {
		t.Errorf("Doctor.Duration = %s, want %s", cfg.Doctor.Duration, want.Doctor.Duration)
	}
	if cfg.Collectors.SyscallLatency != want.Collectors.SyscallLatency {
		t.Errorf("Collectors.SyscallLatency = %v, want %v", cfg.Collectors.SyscallLatency, want.Collectors.SyscallLatency)
	}
	if cfg.Doctor.Thresholds.TCPRetransmitPct != want.Doctor.Thresholds.TCPRetransmitPct {
		t.Errorf("Doctor.Thresholds.TCPRetransmitPct = %v, want %v",
			cfg.Doctor.Thresholds.TCPRetransmitPct, want.Doctor.Thresholds.TCPRetransmitPct)
	}
}

// TestFlattenDefaults checks that the reflection walker produces the expected
// dotted keys, including deeply nested ones, so AutomaticEnv can resolve their
// KERNO_* counterparts.
func TestFlattenDefaults(t *testing.T) {
	keys := make(map[string]any)
	flattenDefaults("", reflect.ValueOf(*Default()), keys)

	want := []string{
		"log_level",
		"ai.api_key",
		"ai.enabled",
		"prometheus.addr",
		"doctor.duration",
		"doctor.thresholds.tcp_retransmit_pct",
		"collectors.syscall_latency",
	}
	for _, k := range want {
		if _, ok := keys[k]; !ok {
			t.Errorf("flattenDefaults() missing key %q", k)
		}
	}
}
