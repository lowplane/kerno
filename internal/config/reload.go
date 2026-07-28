// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

// ReloadResult holds the outcome of a config reload attempt.
type ReloadResult struct {
	// Applied is the list of fields that were updated live.
	Applied []string

	// RestartRequired is the list of fields that changed but need a
	// daemon restart to take effect (e.g. collector toggles tied to
	// already-loaded BPF programs).
	RestartRequired []string
}

// String returns a human-readable summary of the reload result.
func (r ReloadResult) String() string {
	return fmt.Sprintf(
		"config reloaded; %d changes applied; %d changes require restart",
		len(r.Applied), len(r.RestartRequired),
	)
}

// ReloadFrom reads a new config from path (using the same Viper pipeline as
// root.go's initConfig), validates it, diffs it against the receiver, and
// returns the new config together with a change report.
//
// The caller (start.go's SIGHUP handler) is responsible for actually applying
// the changes to live subsystems. This function only does parse + validate +
// diff and returns two lists:
//
//   - result.Applied         — safe to hot-apply right now
//   - result.RestartRequired — changed but needs a full daemon restart
//
// The receiver *c is NOT mutated.
func (c *Config) ReloadFrom(path string) (*Config, ReloadResult, error) {
	next, err := parseConfig(path)
	if err != nil {
		return nil, ReloadResult{}, fmt.Errorf("reload: %w", err)
	}
	if err := next.Validate(); err != nil {
		return nil, ReloadResult{}, fmt.Errorf("reload: invalid config: %w", err)
	}
	result := diff(c, next)
	return next, result, nil
}

// parseConfig mirrors the Viper pipeline in root.go's initConfig so that
// hot-reload honours the same precedence rules:
//
//	env vars > config file > defaults
//
// It intentionally does NOT bind CLI flags (they are one-shot at startup) and
// does NOT call initLogger (the caller does that after the diff is applied).
func parseConfig(path string) (*Config, error) {
	v := viper.New()

	resolved := path
	if resolved == "" {
		resolved = os.Getenv("KERNO_CONFIG")
	}
	if resolved != "" {
		v.SetConfigFile(resolved)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("/etc/kerno")
		v.AddConfigPath("$HOME/.kerno")
		v.AddConfigPath(".")
	}

	v.SetEnvPrefix("KERNO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			if resolved != "" {
				return nil, fmt.Errorf("reading config %q: %w", resolved, err)
			}
		}
	}

	next := Default()
	if err := v.Unmarshal(next); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return next, nil
}

// diff compares two configs and classifies every changed field into
// "can hot-apply" vs "needs restart".
//
// All diffing logic lives here so the SIGHUP handler in start.go consumes
// result.Applied and result.RestartRequired without re-diffing. Adding a new
// config field means updating exactly one place (this function) and one test
// (reload_test.go).
func diff(old, next *Config) ReloadResult {
	var r ReloadResult

	// Always reloadable.
	if old.LogLevel != next.LogLevel {
		r.Applied = append(r.Applied, fmt.Sprintf("log_level: %q -> %q", old.LogLevel, next.LogLevel))
	}
	if old.LogFormat != next.LogFormat {
		r.Applied = append(r.Applied, fmt.Sprintf("log_format: %q -> %q", old.LogFormat, next.LogFormat))
	}
	if old.Prometheus.Addr != next.Prometheus.Addr {
		r.Applied = append(r.Applied, fmt.Sprintf("prometheus.addr: %q -> %q", old.Prometheus.Addr, next.Prometheus.Addr))
	}
	if old.Prometheus.Enabled != next.Prometheus.Enabled {
		r.Applied = append(r.Applied, fmt.Sprintf("prometheus.enabled: %v -> %v", old.Prometheus.Enabled, next.Prometheus.Enabled))
	}
	if !reflect.DeepEqual(old.Doctor.Thresholds, next.Doctor.Thresholds) {
		r.RestartRequired = append(r.RestartRequired, "doctor.thresholds updated (restart required)")
	}
	if old.Doctor.Duration != next.Doctor.Duration {
		r.RestartRequired = append(r.RestartRequired, fmt.Sprintf("doctor.duration: %s -> %s (restart required)", old.Doctor.Duration, next.Doctor.Duration))
	}
	if !reflect.DeepEqual(old.AI, next.AI) {
		r.RestartRequired = append(r.RestartRequired, "ai config updated (restart required)")
	}
	if !reflect.DeepEqual(old.Dashboard, next.Dashboard) {
		r.RestartRequired = append(r.RestartRequired, "dashboard config updated (restart required)")
	}
	if !reflect.DeepEqual(old.Kubernetes, next.Kubernetes) {
		r.RestartRequired = append(r.RestartRequired, "kubernetes config updated (restart required)")
	}

	// Requires restart because BPF programs are already loaded.
	if old.Collectors.SyscallLatency != next.Collectors.SyscallLatency {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.syscall_latency: %v -> %v", old.Collectors.SyscallLatency, next.Collectors.SyscallLatency))
	}
	if old.Collectors.TCPMonitor != next.Collectors.TCPMonitor {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.tcp_monitor: %v -> %v", old.Collectors.TCPMonitor, next.Collectors.TCPMonitor))
	}
	if old.Collectors.OOMTrack != next.Collectors.OOMTrack {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.oom_track: %v -> %v", old.Collectors.OOMTrack, next.Collectors.OOMTrack))
	}
	if old.Collectors.DiskIO != next.Collectors.DiskIO {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.disk_io: %v -> %v", old.Collectors.DiskIO, next.Collectors.DiskIO))
	}
	if old.Collectors.SchedDelay != next.Collectors.SchedDelay {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.sched_delay: %v -> %v", old.Collectors.SchedDelay, next.Collectors.SchedDelay))
	}
	if old.Collectors.FDTrack != next.Collectors.FDTrack {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.fd_track: %v -> %v", old.Collectors.FDTrack, next.Collectors.FDTrack))
	}
	if old.Collectors.FileAudit != next.Collectors.FileAudit {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.file_audit: %v -> %v", old.Collectors.FileAudit, next.Collectors.FileAudit))
	}

	return r
}
