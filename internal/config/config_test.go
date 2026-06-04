// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()

	if cfg.LogLevel != "info" {
		t.Errorf("default LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.LogFormat != "auto" {
		t.Errorf("default LogFormat = %q, want %q", cfg.LogFormat, "auto")
	}
	if cfg.Doctor.Duration != 30*time.Second {
		t.Errorf("default Doctor.Duration = %s, want 30s", cfg.Doctor.Duration)
	}
	if !cfg.Collectors.SyscallLatency {
		t.Error("SyscallLatency should be enabled by default")
	}
	if cfg.Collectors.FileAudit {
		t.Error("FileAudit should be disabled by default")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "default config is valid",
			modify:  func(_ *Config) {},
			wantErr: false,
		},
		{
			name:    "invalid log level",
			modify:  func(c *Config) { c.LogLevel = "verbose" },
			wantErr: true,
		},
		{
			name:    "invalid log format",
			modify:  func(c *Config) { c.LogFormat = "xml" },
			wantErr: true,
		},
		{
			name:    "doctor duration too short",
			modify:  func(c *Config) { c.Doctor.Duration = 500 * time.Millisecond },
			wantErr: true,
		},
		{
			name:    "doctor duration too long",
			modify:  func(c *Config) { c.Doctor.Duration = 10 * time.Minute },
			wantErr: true,
		},
		{
			name: "prometheus enabled without addr",
			modify: func(c *Config) {
				c.Prometheus.Enabled = true
				c.Prometheus.Addr = ""
			},
			wantErr: true,
		},
		{
			name: "dashboard enabled without addr",
			modify: func(c *Config) {
				c.Dashboard.Enabled = true
				c.Dashboard.Addr = ""
			},
			wantErr: true,
		},
		{
			name: "prometheus disabled without addr is fine",
			modify: func(c *Config) {
				c.Prometheus.Enabled = false
				c.Prometheus.Addr = ""
			},
			wantErr: false,
		},
		{
			name: "ai max_tokens must be positive",
			modify: func(c *Config) {
				c.AI.Enabled = true
				c.AI.Provider = "ollama"
				c.AI.MaxTokens = 0
			},
			wantErr: true,
		},
		{
			name: "ai max_tokens negative",
			modify: func(c *Config) {
				c.AI.Enabled = true
				c.AI.Provider = "ollama"
				c.AI.MaxTokens = -1
			},
			wantErr: true,
		},
		{
			name: "ai rate_limit_per_minute may not be negative",
			modify: func(c *Config) {
				c.AI.Enabled = true
				c.AI.Provider = "ollama"
				c.AI.RateLimitPerMinute = -1
			},
			wantErr: true,
		},
		{
			name: "ai rate_limit_per_minute zero means unlimited",
			modify: func(c *Config) {
				c.AI.Enabled = true
				c.AI.Provider = "ollama"
				c.AI.RateLimitPerMinute = 0
			},
			wantErr: false,
		},
		{
			name: "ai temperature below zero",
			modify: func(c *Config) {
				c.AI.Enabled = true
				c.AI.Provider = "ollama"
				c.AI.Temperature = -0.1
			},
			wantErr: true,
		},
		{
			name: "ai temperature above one",
			modify: func(c *Config) {
				c.AI.Enabled = true
				c.AI.Provider = "ollama"
				c.AI.Temperature = 1.1
			},
			wantErr: true,
		},
		{
			name: "ai temperature at zero lower bound",
			modify: func(c *Config) {
				c.AI.Enabled = true
				c.AI.Provider = "ollama"
				c.AI.Temperature = 0.0
			},
			wantErr: false,
		},
		{
			name: "ai temperature at one upper bound",
			modify: func(c *Config) {
				c.AI.Enabled = true
				c.AI.Provider = "ollama"
				c.AI.Temperature = 1.0
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
