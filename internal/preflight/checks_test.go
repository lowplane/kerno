// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		release     string
		wantMajor   int
		wantMinor   int
		expectError bool
	}{
		{"6.17.0", 6, 17, false},
		{"5.15.0-91-generic", 5, 15, false},           // Ubuntu
		{"5.14.0-70.13.1.el9_0.x86_64", 5, 14, false}, // RHEL
		{"6.1.0-rc4", 6, 1, false},                    // release candidate
		{"5.8.0+debug", 5, 8, false},                  // custom build
		{"5.4.0", 5, 4, false},
		{"4.19.0", 4, 19, false},
		{"invalid", 0, 0, true},
		{"", 0, 0, true},
		{"abc.def", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.release, func(t *testing.T) {
			major, minor, err := parseKernelVersion(tt.release)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for %q, got (%d, %d)", tt.release, major, minor)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.release, err)
			}
			if major != tt.wantMajor || minor != tt.wantMinor {
				t.Errorf("parseKernelVersion(%q) = (%d, %d), want (%d, %d)",
					tt.release, major, minor, tt.wantMajor, tt.wantMinor)
			}
		})
	}
}

func TestCheckBTF_Present(t *testing.T) {
	dir := t.TempDir()
	btfPath := filepath.Join(dir, "vmlinux")
	if err := os.WriteFile(btfPath, []byte("fake-btf"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := CheckBTF(CheckOptions{BTFPath: btfPath})
	if r.Status != StatusPass {
		t.Errorf("expected PASS, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckBTF_Missing(t *testing.T) {
	r := CheckBTF(CheckOptions{BTFPath: "/nonexistent/vmlinux"})
	if r.Status != StatusFail {
		t.Errorf("expected FAIL, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckProcReadable(t *testing.T) {
	dir := t.TempDir()
	versionPath := filepath.Join(dir, "version")
	if err := os.WriteFile(versionPath, []byte("Linux version 6.17.0"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := CheckProcReadable(CheckOptions{ProcPath: dir})
	if r.Status != StatusPass {
		t.Errorf("expected PASS, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckProcUnreadable(t *testing.T) {
	r := CheckProcReadable(CheckOptions{ProcPath: "/nonexistent"})
	if r.Status != StatusFail {
		t.Errorf("expected FAIL, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckOutputDir_Writable(t *testing.T) {
	dir := t.TempDir()
	r := CheckOutputDir(CheckOptions{OutputDir: dir})
	if r.Status != StatusPass {
		t.Errorf("expected PASS, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckOutputDir_NonExistent(t *testing.T) {
	r := CheckOutputDir(CheckOptions{OutputDir: "/nonexistent/output"})
	if r.Status != StatusFail {
		t.Errorf("expected FAIL, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckPortFree_Available(t *testing.T) {
	// Use port 0 to get an available port.
	r := CheckPortFree(CheckOptions{PromAddr: "127.0.0.1:0"})
	if r.Status != StatusPass {
		t.Errorf("expected PASS, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckPortFree_InUse(t *testing.T) {
	// Bind a port, then check it reports FAIL.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	r := CheckPortFree(CheckOptions{PromAddr: addr})
	if r.Status != StatusFail {
		t.Errorf("expected FAIL for in-use port %s, got %v: %s", addr, r.Status, r.Message)
	}
}

func TestCheckTracefs_TraceFSPresent(t *testing.T) {
	dir := t.TempDir()
	traceFSPath := filepath.Join(dir, "tracing")
	if err := os.Mkdir(traceFSPath, 0o755); err != nil {
		t.Fatal(err)
	}

	r := CheckTracefs(CheckOptions{
		TraceFSPath: traceFSPath,
		DebugFSPath: filepath.Join(dir, "debug"),
	})
	if r.Status != StatusPass {
		t.Errorf("expected PASS, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckTracefs_DebugFSPresent(t *testing.T) {
	dir := t.TempDir()
	debugTracing := filepath.Join(dir, "debug", "tracing")
	if err := os.MkdirAll(debugTracing, 0o755); err != nil {
		t.Fatal(err)
	}

	r := CheckTracefs(CheckOptions{
		TraceFSPath: filepath.Join(dir, "nonexistent"),
		DebugFSPath: filepath.Join(dir, "debug"),
	})
	if r.Status != StatusPass {
		t.Errorf("expected PASS, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckTracefs_NeitherPresent(t *testing.T) {
	dir := t.TempDir()
	r := CheckTracefs(CheckOptions{
		TraceFSPath: filepath.Join(dir, "nonexistent"),
		DebugFSPath: filepath.Join(dir, "also-nonexistent"),
	})
	if r.Status != StatusWarn {
		t.Errorf("expected WARN, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckCap_HasCap(t *testing.T) {
	// Synthetic caps with CAP_BPF set (bit 39).
	caps := uint64(1) << capBPF
	r := CheckCapBPF(caps, nil)
	if r.Status != StatusPass {
		t.Errorf("expected PASS for CAP_BPF, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckCap_MissingCap(t *testing.T) {
	caps := uint64(0)

	// CAP_BPF missing should FAIL.
	r := CheckCapBPF(caps, nil)
	if r.Status != StatusFail {
		t.Errorf("expected FAIL for missing CAP_BPF, got %v: %s", r.Status, r.Message)
	}

	// CAP_NET_ADMIN missing should WARN (degraded, not blocked).
	r = CheckCapNetAdmin(caps, nil)
	if r.Status != StatusWarn {
		t.Errorf("expected WARN for missing CAP_NET_ADMIN, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckCap_CapgetError(t *testing.T) {
	err := os.ErrPermission
	r := CheckCapBPF(0, err)
	if r.Status != StatusFail {
		t.Errorf("expected FAIL on capget error, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckCapPerfmon_HasCap(t *testing.T) {
	caps := uint64(1) << capPerfmon
	r := CheckCapPerfmon(caps, nil)
	if r.Status != StatusPass {
		t.Errorf("expected PASS for CAP_PERFMON, got %v: %s", r.Status, r.Message)
	}
}

func TestCheckCapPerfmon_MissingCap(t *testing.T) {
	r := CheckCapPerfmon(0, nil)
	if r.Status != StatusFail {
		t.Errorf("expected FAIL for missing CAP_PERFMON, got %v: %s", r.Status, r.Message)
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{StatusPass, "PASS"},
		{StatusWarn, "WARN"},
		{StatusFail, "FAIL"},
		{Status(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("Status(%d).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestRunAll_ResultCount(t *testing.T) {
	// RunAll with defaults will try real system paths. We just verify the
	// count is correct (10 checks).
	results := RunAll(CheckOptions{})
	if len(results) != 10 {
		t.Errorf("RunAll returned %d results, want 10", len(results))
	}
}
