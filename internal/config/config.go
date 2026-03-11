// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

// Package config defines the global configuration for Kerno.
// Configuration is loaded from file, environment variables, and CLI flags
// using Viper with the following precedence: flags > env > file > defaults.
package config

import (
	"fmt"
	"time"
)

// Config is the root configuration structure for Kerno.
type Config struct {
	// LogLevel is the logging verbosity: debug, info, warn, error.
	LogLevel string `mapstructure:"log_level" json:"logLevel"`

	// LogFormat is the log output format: text, json.
	LogFormat string `mapstructure:"log_format" json:"logFormat"`

	// Collectors enables or disables specific signal collectors.
	Collectors CollectorsConfig `mapstructure:"collectors" json:"collectors"`

	// Doctor configures the kerno doctor analysis engine.
	Doctor DoctorConfig `mapstructure:"doctor" json:"doctor"`

	// Prometheus configures the Prometheus metrics exporter.
	Prometheus PrometheusConfig `mapstructure:"prometheus" json:"prometheus"`

	// Dashboard configures the embedded web dashboard.
	Dashboard DashboardConfig `mapstructure:"dashboard" json:"dashboard"`

	// Kubernetes configures the K8s adapter for pod enrichment.
	Kubernetes KubernetesConfig `mapstructure:"kubernetes" json:"kubernetes"`
}

// CollectorsConfig controls which signal collectors are active.
type CollectorsConfig struct {
	SyscallLatency bool `mapstructure:"syscall_latency" json:"syscallLatency"`
	TCPMonitor     bool `mapstructure:"tcp_monitor" json:"tcpMonitor"`
	OOMTrack       bool `mapstructure:"oom_track" json:"oomTrack"`
	DiskIO         bool `mapstructure:"disk_io" json:"diskIO"`
	SchedDelay     bool `mapstructure:"sched_delay" json:"schedDelay"`
	FDTrack        bool `mapstructure:"fd_track" json:"fdTrack"`
	FileAudit      bool `mapstructure:"file_audit" json:"fileAudit"`
}

// DoctorConfig controls the diagnostic analysis engine.
type DoctorConfig struct {
	// Duration is how long doctor collects signals before analysis.
	Duration time.Duration `mapstructure:"duration" json:"duration"`

	// Thresholds for diagnostic rules.
	Thresholds DoctorThresholds `mapstructure:"thresholds" json:"thresholds"`
}

// DoctorThresholds defines the trigger thresholds for diagnostic rules.
type DoctorThresholds struct {
	SyscallP99WarningNs  int64   `mapstructure:"syscall_p99_warning_ns" json:"syscallP99WarningNs"`
	SyscallP99CriticalNs int64   `mapstructure:"syscall_p99_critical_ns" json:"syscallP99CriticalNs"`
	TCPRetransmitPct     float64 `mapstructure:"tcp_retransmit_pct" json:"tcpRetransmitPct"`
	OOMMemoryPct         float64 `mapstructure:"oom_memory_pct" json:"oomMemoryPct"`
	DiskP99WarningNs     int64   `mapstructure:"disk_p99_warning_ns" json:"diskP99WarningNs"`
	DiskP99CriticalNs    int64   `mapstructure:"disk_p99_critical_ns" json:"diskP99CriticalNs"`
	SchedDelayWarningNs  int64   `mapstructure:"sched_delay_warning_ns" json:"schedDelayWarningNs"`
	SchedDelayCriticalNs int64   `mapstructure:"sched_delay_critical_ns" json:"schedDelayCriticalNs"`
	FDGrowthPerSec       float64 `mapstructure:"fd_growth_per_sec" json:"fdGrowthPerSec"`
}

// PrometheusConfig controls the Prometheus metrics exporter.
type PrometheusConfig struct {
	Enabled bool   `mapstructure:"enabled" json:"enabled"`
	Addr    string `mapstructure:"addr" json:"addr"`
}

// DashboardConfig controls the embedded web dashboard.
type DashboardConfig struct {
	Enabled bool   `mapstructure:"enabled" json:"enabled"`
	Addr    string `mapstructure:"addr" json:"addr"`
}

// KubernetesConfig controls the Kubernetes adapter.
type KubernetesConfig struct {
	Enabled    bool   `mapstructure:"enabled" json:"enabled"`
	Kubeconfig string `mapstructure:"kubeconfig" json:"kubeconfig"`
}

// Default returns the default configuration.
func Default() *Config {
	return &Config{
		LogLevel:  "info",
		LogFormat: "text",
		Collectors: CollectorsConfig{
			SyscallLatency: true,
			TCPMonitor:     true,
			OOMTrack:       true,
			DiskIO:         true,
			SchedDelay:     true,
			FDTrack:        true,
			FileAudit:      false, // opt-in: can be noisy
		},
		Doctor: DoctorConfig{
			Duration: 30 * time.Second,
			Thresholds: DoctorThresholds{
				SyscallP99WarningNs:  100_000_000,  // 100ms
				SyscallP99CriticalNs: 500_000_000,  // 500ms
				TCPRetransmitPct:     2.0,           // 2%
				OOMMemoryPct:         90.0,          // 90%
				DiskP99WarningNs:     50_000_000,    // 50ms
				DiskP99CriticalNs:    200_000_000,   // 200ms
				SchedDelayWarningNs:  5_000_000,     // 5ms
				SchedDelayCriticalNs: 20_000_000,    // 20ms
				FDGrowthPerSec:       10.0,          // 10 FDs/sec
			},
		},
		Prometheus: PrometheusConfig{
			Enabled: true,
			Addr:    ":9090",
		},
		Dashboard: DashboardConfig{
			Enabled: false,
			Addr:    ":8080",
		},
		Kubernetes: KubernetesConfig{
			Enabled:    false,
			Kubeconfig: "",
		},
	}
}

// Validate checks that the configuration values are sane.
func (c *Config) Validate() error {
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid log_level %q: must be one of debug, info, warn, error", c.LogLevel)
	}

	switch c.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("invalid log_format %q: must be text or json", c.LogFormat)
	}

	if c.Doctor.Duration < time.Second {
		return fmt.Errorf("doctor.duration must be at least 1s, got %s", c.Doctor.Duration)
	}
	if c.Doctor.Duration > 5*time.Minute {
		return fmt.Errorf("doctor.duration must be at most 5m, got %s", c.Doctor.Duration)
	}

	if c.Prometheus.Enabled && c.Prometheus.Addr == "" {
		return fmt.Errorf("prometheus.addr must be set when prometheus is enabled")
	}

	if c.Dashboard.Enabled && c.Dashboard.Addr == "" {
		return fmt.Errorf("dashboard.addr must be set when dashboard is enabled")
	}

	return nil
}
