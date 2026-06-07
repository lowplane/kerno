// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCgroupDir creates a simulated cgroup v2 directory tree under dir.
func writeCgroupDir(t *testing.T, root string, limitBytes, currentBytes, highBytes uint64, eventsHigh uint64) string {
	t.Helper()
	cgroupPath := filepath.Join(root, "kubepods", "burstable", "pod-test", "container-0")
	if err := os.MkdirAll(cgroupPath, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile := func(name, content string) {
		if err := os.WriteFile(filepath.Join(cgroupPath, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("memory.max", fmt.Sprintf("%d\n", limitBytes))
	writeFile("memory.current", fmt.Sprintf("%d\n", currentBytes))
	writeFile("memory.high", fmt.Sprintf("%d\n", highBytes))
	writeFile("memory.events", fmt.Sprintf("low 0\nhigh %d\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n", eventsHigh))
	return cgroupPath
}

func TestCgroupMemoryCollector_BasicPoll(t *testing.T) {
	tests := []struct {
		name         string
		limitBytes   uint64
		currentBytes uint64
		highBytes    uint64
		wantUsedLow  float64
		wantUsedHigh float64
	}{
		{
			name:         "normal usage 75 percent",
			limitBytes:   4 << 30,
			currentBytes: 3 << 30,
			highBytes:    uint64(4<<30) * 9 / 10,
			wantUsedLow:  74.0,
			wantUsedHigh: 76.0,
		},
		{
			name:         "at high threshold 90 percent",
			limitBytes:   4 << 30,
			currentBytes: uint64(4<<30) * 9 / 10, // current == high
			highBytes:    uint64(4<<30) * 9 / 10,
			wantUsedLow:  89.0,
			wantUsedHigh: 91.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeCgroupDir(t, root, tc.limitBytes, tc.currentBytes, tc.highBytes, 0)

			c := NewCgroupMemoryCollector(newSilentLogger(), 50*time.Millisecond)
			c.cgroupRoot = root

			if err := c.poll(); err != nil {
				t.Fatal(err)
			}

			snap := c.Snapshot().(*CgroupMemorySnapshot)
			if snap == nil || len(snap.Containers) == 0 {
				t.Fatal("expected containers in snapshot")
			}

			e := snap.Containers[0]

			if e.LimitBytes != tc.limitBytes {
				t.Errorf("LimitBytes = %d, want %d", e.LimitBytes, tc.limitBytes)
			}
			if e.CurrentBytes != tc.currentBytes {
				t.Errorf("CurrentBytes = %d, want %d", e.CurrentBytes, tc.currentBytes)
			}
			if e.HighBytes != tc.highBytes {
				t.Errorf("HighBytes = %d, want %d", e.HighBytes, tc.highBytes)
			}
			if e.UsedPct < tc.wantUsedLow || e.UsedPct > tc.wantUsedHigh {
				t.Errorf("UsedPct = %.1f, want between %.1f and %.1f",
					e.UsedPct, tc.wantUsedLow, tc.wantUsedHigh)
			}
		})
	}
}

func TestCgroupMemoryCollector_UnlimitedMax(t *testing.T) {
	root := t.TempDir()
	cgroupPath := filepath.Join(root, "container-unlimited")
	if err := os.MkdirAll(cgroupPath, 0o750); err != nil {
		t.Fatal(err)
	}
	// memory.max = "max" means unlimited — should be ignored.
	if err := os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("max\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgroupPath, "memory.current"), []byte("1073741824\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := NewCgroupMemoryCollector(newSilentLogger(), 50*time.Millisecond)
	c.cgroupRoot = root

	if err := c.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if snap := c.Snapshot(); snap != nil {
		s := snap.(*CgroupMemorySnapshot)
		for _, e := range s.Containers {
			if e.LimitBytes == 0 {
				t.Error("container with memory.max=max should not appear in snapshot")
			}
		}
	}
}

func TestCgroupMemoryCollector_GrowthRate(t *testing.T) {
	tests := []struct {
		name      string
		initialMB int
		finalMB   int
		wantPos   bool
	}{
		{
			name:      "positive growth",
			initialMB: 700,
			finalMB:   800,
			wantPos:   true,
		},
		{
			name:      "negative growth",
			initialMB: 800,
			finalMB:   700,
			wantPos:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()

			const limitBytes = 1 << 30

			cgPath := writeCgroupDir(
				t,
				root,
				limitBytes,
				uint64(tc.initialMB)<<20,
				limitBytes*9/10,
				0,
			)

			c := NewCgroupMemoryCollector(newSilentLogger(), 10*time.Millisecond)
			c.cgroupRoot = root

			if err := c.poll(); err != nil {
				t.Fatal(err)
			}

			time.Sleep(50 * time.Millisecond)

			if err := os.WriteFile(
				filepath.Join(cgPath, "memory.current"),
				[]byte(fmt.Sprintf("%d\n", uint64(tc.finalMB)<<20)),
				0o600,
			); err != nil {
				t.Fatal(err)
			}

			if err := c.poll(); err != nil {
				t.Fatal(err)
			}

			snap := c.Snapshot().(*CgroupMemorySnapshot)

			if len(snap.Containers) == 0 {
				t.Fatal("expected containers in snapshot")
			}

			rate := snap.Containers[0].GrowthRateBytesPerSec

			if tc.wantPos && rate <= 0 {
				t.Errorf("GrowthRateBytesPerSec = %v, want > 0", rate)
			}

			if !tc.wantPos && rate >= 0 {
				t.Errorf("GrowthRateBytesPerSec = %v, want < 0", rate)
			}
		})
	}
}

func TestCgroupMemoryCollector_HighEventRate(t *testing.T) {
	root := t.TempDir()
	const limitBytes = 1 << 30
	cgPath := writeCgroupDir(t, root, limitBytes, 900<<20, limitBytes*9/10, 5)

	c := NewCgroupMemoryCollector(newSilentLogger(), 10*time.Millisecond)
	c.cgroupRoot = root

	if err := c.poll(); err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)
	// Increment high event counter by 10.
	events := "low 0\nhigh 15\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n"
	if err := os.WriteFile(filepath.Join(cgPath, "memory.events"), []byte(events), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := c.poll(); err != nil {
		t.Fatal(err)
	}

	snap := c.Snapshot().(*CgroupMemorySnapshot)
	if len(snap.Containers) == 0 {
		t.Fatal("expected containers in snapshot")
	}
	if snap.Containers[0].HighEventRate <= 0 {
		t.Errorf("HighEventRate = %v, want > 0", snap.Containers[0].HighEventRate)
	}
}

func TestCgroupMemoryCollector_EmptyRoot(t *testing.T) {
	root := t.TempDir() // empty — no cgroup files

	c := NewCgroupMemoryCollector(newSilentLogger(), 50*time.Millisecond)
	c.cgroupRoot = root

	if err := c.poll(); err != nil {
		t.Fatalf("poll on empty root should not error: %v", err)
	}
	if snap := c.Snapshot(); snap != nil {
		t.Error("expected nil snapshot for empty cgroup root")
	}
}

func TestCgroupMemoryCollector_StartStop(t *testing.T) {
	root := t.TempDir()
	writeCgroupDir(t, root, 2<<30, 1<<30, 0, 0)

	c := NewCgroupMemoryCollector(newSilentLogger(), 20*time.Millisecond)
	c.cgroupRoot = root

	ctx, cancel := context.WithCancel(context.Background())
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	cancel()
	c.Stop()

	if c.Snapshot() == nil {
		t.Error("expected non-nil snapshot after Start+polls")
	}
}

// TestCgroupMemoryCollector_LeafOnly verifies that when a parent directory
// and its direct child both have a finite memory.max — as in a real K8s
// hierarchy (kubepods.slice → pod-x.slice → container.scope) — only the
// innermost leaf is reported, not the parent.
func TestCgroupMemoryCollector_LeafOnly(t *testing.T) {
	root := t.TempDir()
	writeAt := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Parent slice — has memory.max but must NOT appear because its child also has one.
	parent := filepath.Join(root, "kubepods.slice", "pod-x.slice")
	if err := os.MkdirAll(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	writeAt(filepath.Join(parent, "memory.max"), "8589934592\n")     // 8 GiB
	writeAt(filepath.Join(parent, "memory.current"), "4294967296\n") // 4 GiB
	writeAt(filepath.Join(parent, "memory.high"), "7516192768\n")
	writeAt(filepath.Join(parent, "memory.events"), "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n")

	// Leaf container scope — direct child of parent; this is the only entry that should appear.
	leaf := filepath.Join(parent, "container.scope")
	if err := os.MkdirAll(leaf, 0o750); err != nil {
		t.Fatal(err)
	}
	writeAt(filepath.Join(leaf, "memory.max"), "4294967296\n")     // 4 GiB
	writeAt(filepath.Join(leaf, "memory.current"), "3865470566\n") // ~90 %
	writeAt(filepath.Join(leaf, "memory.high"), "3865470566\n")
	writeAt(filepath.Join(leaf, "memory.events"), "low 0\nhigh 2\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n")

	c := NewCgroupMemoryCollector(newSilentLogger(), 50*time.Millisecond)
	c.cgroupRoot = root

	if err := c.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}

	snap, ok := c.Snapshot().(*CgroupMemorySnapshot)
	if !ok || snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if len(snap.Containers) != 1 {
		t.Fatalf("leaf-only: expected 1 entry, got %d (parent was incorrectly included)", len(snap.Containers))
	}
	if !strings.Contains(snap.Containers[0].CgroupPath, "container.scope") {
		t.Errorf("expected leaf path (container.scope), got %q", snap.Containers[0].CgroupPath)
	}
}

func TestReadCgroupMemoryEvents(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    map[string]uint64
	}{
		{
			name:    "full events file",
			content: "low 0\nhigh 4\nmax 2\noom 1\noom_kill 1\noom_group_kill 0\n",
			want: map[string]uint64{
				"low":            0,
				"high":           4,
				"max":            2,
				"oom":            1,
				"oom_kill":       1,
				"oom_group_kill": 0,
			},
		},
		{
			name:    "empty file",
			content: "",
			want:    map[string]uint64{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "memory.events")

			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}

			got := readCgroupMemoryEvents(path)

			for k, want := range tc.want {
				if got[k] != want {
					t.Errorf("events[%q] = %d, want %d", k, got[k], want)
				}
			}
		})
	}
}

func TestParseCgroupPod(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantPod string
	}{
		{
			name:    "kubernetes pod uid",
			path:    "/sys/fs/cgroup/kubepods/burstable/poda1b2c3d4/container-xyz",
			wantPod: "poda1b2c3d4",
		},
		{
			name:    "pod with hyphen",
			path:    "/sys/fs/cgroup/kubepods/guaranteed/pod-foo-bar/ctr0",
			wantPod: "pod-foo-bar",
		},
		{
			name:    "docker scope fallback",
			path:    "/sys/fs/cgroup/system.slice/docker-abc123.scope",
			wantPod: "docker-abc123.scope",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCgroupPod(tc.path)

			if got == "" {
				t.Errorf("parseCgroupPod(%q) returned empty pod", tc.path)
			}

			if got != tc.wantPod {
				t.Errorf("parseCgroupPod(%q) = %q, want %q", tc.path, got, tc.wantPod)
			}
		})
	}
}

// TestReadCgroupMemoryMax verifies parsing of finite and unlimited memory limits.
func TestReadCgroupMemoryMax(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantVal uint64
		wantOK  bool
	}{
		{
			name:    "max literal",
			content: "max\n",
			wantVal: 0,
			wantOK:  false,
		},
		{
			name:    "numeric limit",
			content: "1073741824\n",
			wantVal: 1073741824,
			wantOK:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()

			path := filepath.Join(dir, "memory.max")

			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}

			gotVal, gotOK := readCgroupMemoryMax(path)

			if gotVal != tc.wantVal {
				t.Fatalf("got %d want %d", gotVal, tc.wantVal)
			}

			if gotOK != tc.wantOK {
				t.Fatalf("got %v want %v", gotOK, tc.wantOK)
			}
		})
	}
}
