// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"log/slog"
	"testing"
)

// ─── DetectEnvironment ────────────────────────────────────────────────────

func TestDetectEnvironment_DefaultsToBareMetal(t *testing.T) {
	// In test environments (no K8s token, may or may not have systemd).
	env := DetectEnvironment()
	if env != EnvBareMetal && env != EnvSystemd {
		t.Errorf("expected baremetal or systemd, got %q", env)
	}
}

// ─── parseCgroupPath ──────────────────────────────────────────────────────

func TestParseCgroupPath(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			"cgroup v2",
			"0::/system.slice/nginx.service\n",
			"/system.slice/nginx.service",
		},
		{
			"cgroup v1 memory",
			"12:memory:/kubepods/burstable/pod123\n5:cpu:/kubepods/burstable/pod123\n",
			"/kubepods/burstable/pod123",
		},
		{
			"empty",
			"",
			"",
		},
		{
			"cgroup v2 root",
			"0::/\n",
			"/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCgroupPath(tt.content)
			if got != tt.want {
				t.Errorf("parseCgroupPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ─── BareMetalAdapter ─────────────────────────────────────────────────────

func TestBareMetalAdapter(t *testing.T) {
	a := NewBareMetalAdapter(slog.Default())

	if a.Name() != "baremetal" {
		t.Errorf("Name() = %q, want %q", a.Name(), "baremetal")
	}

	if err := a.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	meta := &EventMeta{}
	a.Enrich(meta)
	if meta.Hostname == "" {
		t.Error("expected non-empty hostname after Enrich")
	}

	a.Stop()
}

// ─── SystemdAdapter ───────────────────────────────────────────────────────

func TestParseSystemdCgroup(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		unit  string
		slice string
		scope string
	}{
		{
			"nginx service",
			"/system.slice/nginx.service",
			"nginx.service", "system.slice", "",
		},
		{
			"user session scope",
			"/user.slice/user-1000.slice/session-2.scope",
			"", "user.slice/user-1000.slice", "session-2.scope",
		},
		{
			"docker scope",
			"/system.slice/docker-abc123.scope",
			"", "system.slice", "docker-abc123.scope",
		},
		{
			"empty path",
			"",
			"", "", "",
		},
		{
			"root",
			"/",
			"", "", "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit, slice, scope := parseSystemdCgroup(tt.path)
			if unit != tt.unit {
				t.Errorf("unit = %q, want %q", unit, tt.unit)
			}
			if slice != tt.slice {
				t.Errorf("slice = %q, want %q", slice, tt.slice)
			}
			if scope != tt.scope {
				t.Errorf("scope = %q, want %q", scope, tt.scope)
			}
		})
	}
}

func TestSystemdAdapter(t *testing.T) {
	a := NewSystemdAdapter(slog.Default())

	if a.Name() != "systemd" {
		t.Errorf("Name() = %q, want %q", a.Name(), "systemd")
	}

	if err := a.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	meta := &EventMeta{
		CgroupPath: "/system.slice/nginx.service",
	}
	a.Enrich(meta)

	if meta.Unit != "nginx.service" {
		t.Errorf("Unit = %q, want %q", meta.Unit, "nginx.service")
	}
	if meta.Slice != "system.slice" {
		t.Errorf("Slice = %q, want %q", meta.Slice, "system.slice")
	}

	a.Stop()
}

// ─── KubernetesAdapter ────────────────────────────────────────────────────

func TestExtractPodUID(t *testing.T) {
	tests := []struct {
		name  string
		cpath string
		want  string
	}{
		{
			"cgroup v1",
			"/kubepods/burstable/pod12345678-1234-1234-1234-123456789abc/abc123",
			"12345678-1234-1234-1234-123456789abc",
		},
		{
			"cgroup v2 systemd driver",
			"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789abc.slice/cri-containerd-xyz.scope",
			"12345678-1234-1234-1234-123456789abc",
		},
		{
			"no pod UID",
			"/system.slice/nginx.service",
			"",
		},
		{
			"empty",
			"",
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPodUID(tt.cpath)
			if got != tt.want {
				t.Errorf("extractPodUID(%q) = %q, want %q", tt.cpath, got, tt.want)
			}
		})
	}
}

func TestExtractDeploymentName(t *testing.T) {
	tests := []struct {
		rs   string
		want string
	}{
		{"nginx-deployment-5d8f4c7b9", "nginx-deployment"},
		{"my-app-7f6b8c9d4", "my-app"},
		{"simple", "simple"},
	}
	for _, tt := range tests {
		t.Run(tt.rs, func(t *testing.T) {
			if got := extractDeploymentName(tt.rs); got != tt.want {
				t.Errorf("extractDeploymentName(%q) = %q, want %q", tt.rs, got, tt.want)
			}
		})
	}
}

func TestIsUIDLike(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"12345678-1234-1234-1234-123456789abc", true},
		{"12345678_1234_1234_1234_123456789abc", true},
		{"short", false},
		{"12345678-1234-1234-1234-123456789XYZ", false}, // uppercase
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isUIDLike(tt.s); got != tt.want {
				t.Errorf("isUIDLike(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestKubernetesAdapter_Enrich(t *testing.T) {
	a := NewKubernetesAdapter(slog.Default())

	// Populate the index directly (same package access).
	a.uidIndex["12345678-1234-1234-1234-123456789abc"] = &PodInfo{
		Name:       "nginx-abc-123",
		Namespace:  "default",
		Node:       "worker-1",
		Deployment: "nginx",
		UID:        "12345678-1234-1234-1234-123456789abc",
	}

	meta := &EventMeta{
		CgroupPath: "/kubepods/burstable/pod12345678-1234-1234-1234-123456789abc/container-xyz",
	}
	a.Enrich(meta)

	if meta.Pod != "nginx-abc-123" {
		t.Errorf("Pod = %q, want %q", meta.Pod, "nginx-abc-123")
	}
	if meta.Namespace != "default" {
		t.Errorf("Namespace = %q, want %q", meta.Namespace, "default")
	}
	if meta.Deployment != "nginx" {
		t.Errorf("Deployment = %q, want %q", meta.Deployment, "nginx")
	}
}

func TestKubernetesAdapter_EnrichNoMatch(t *testing.T) {
	a := NewKubernetesAdapter(slog.Default())

	meta := &EventMeta{
		CgroupPath: "/system.slice/nginx.service",
	}
	a.Enrich(meta)

	if meta.Pod != "" {
		t.Errorf("Pod = %q, want empty", meta.Pod)
	}
}
