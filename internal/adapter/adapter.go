// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package adapter provides environment adapters that enrich kernel events
// with context metadata (hostname, K8s pod/namespace, systemd unit, etc.).
//
// The adapter layer sits between raw BPF events and the metrics/doctor
// consumers. It mutates events in place to add environment-specific fields
// so that downstream consumers don't need to know where Kerno is running.
package adapter

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// EventMeta holds enrichment metadata that adapters attach to events.
// Consumers read these fields for Prometheus labels, doctor findings, etc.
type EventMeta struct {
	// Bare metal fields (always populated).
	Hostname string `json:"hostname"`
	Comm     string `json:"comm,omitempty"`
	PID      uint32 `json:"pid,omitempty"`

	// Kubernetes fields (populated when running in K8s).
	Pod        string `json:"pod,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Node       string `json:"node,omitempty"`
	Deployment string `json:"deployment,omitempty"`
	Container  string `json:"container,omitempty"`

	// Systemd fields (populated when running under systemd).
	Unit  string `json:"unit,omitempty"`
	Slice string `json:"slice,omitempty"`
	Scope string `json:"scope,omitempty"`

	// CgroupPath is the raw cgroup path for the process.
	CgroupPath string `json:"cgroupPath,omitempty"`
}

// Adapter enriches events with environment-specific metadata.
type Adapter interface {
	// Name returns the adapter identifier (e.g., "baremetal", "kubernetes", "systemd").
	Name() string

	// Start initializes the adapter (e.g., starts K8s informers).
	// The adapter runs until the context is canceled.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the adapter.
	Stop()

	// Enrich adds environment metadata to the given EventMeta based on PID/cgroup.
	Enrich(meta *EventMeta)
}

// Environment represents the detected runtime environment.
type Environment string

const (
	EnvBareMetal  Environment = "baremetal"
	EnvKubernetes Environment = "kubernetes"
	EnvSystemd    Environment = "systemd"
)

// DetectEnvironment probes the runtime to determine where Kerno is running.
// Detection order: Kubernetes (service account token) → Systemd (cgroup) → Bare metal.
func DetectEnvironment() Environment {
	// Check for Kubernetes service account token.
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return EnvKubernetes
	}

	// Check for systemd cgroup hierarchy.
	if isSystemdManaged() {
		return EnvSystemd
	}

	return EnvBareMetal
}

// isSystemdManaged checks if the init process is systemd by reading /proc/1/comm.
func isSystemdManaged() bool {
	data, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		return false
	}
	comm := string(data)
	return len(comm) >= 7 && comm[:7] == "systemd"
}

// NewAdapter creates the appropriate adapter for the detected environment.
// It auto-detects the environment unless overridden by config.
func NewAdapter(logger *slog.Logger, env Environment) Adapter {
	switch env {
	case EnvKubernetes:
		return NewKubernetesAdapter(logger)
	case EnvSystemd:
		return NewSystemdAdapter(logger)
	default:
		return NewBareMetalAdapter(logger)
	}
}

// cgroupPathForPID reads the cgroup path for a given PID from /proc.
// Works with both cgroup v1 and v2.
func cgroupPathForPID(pid uint32) string {
	// cgroup v2: single line in /proc/PID/cgroup with "0::" prefix.
	// cgroup v1: multiple lines; we look for the one with memory controller.
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return parseCgroupPath(string(data))
}

// parseCgroupPath extracts the cgroup path from /proc/PID/cgroup content.
func parseCgroupPath(content string) string {
	// Parse line by line. cgroup v2 has "0::<path>".
	// cgroup v1 has multiple lines like "12:memory:<path>".
	for i := 0; i < len(content); {
		end := i
		for end < len(content) && content[end] != '\n' {
			end++
		}
		line := content[i:end]
		if end < len(content) {
			i = end + 1
		} else {
			i = end
		}

		// cgroup v2: "0::<path>"
		if len(line) > 3 && line[0] == '0' && line[1] == ':' && line[2] == ':' {
			return line[3:]
		}
	}

	// Fallback: return first non-empty path from any controller.
	for i := 0; i < len(content); {
		end := i
		for end < len(content) && content[end] != '\n' {
			end++
		}
		line := content[i:end]
		if end < len(content) {
			i = end + 1
		} else {
			i = end
		}

		// Find the last ':' — path is after it.
		lastColon := -1
		for j := len(line) - 1; j >= 0; j-- {
			if line[j] == ':' {
				lastColon = j
				break
			}
		}
		if lastColon >= 0 && lastColon < len(line)-1 {
			return line[lastColon+1:]
		}
	}
	return ""
}
