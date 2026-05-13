// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	root := t.TempDir()
	const limitBytes = 4 << 30   // 4 GiB
	const currentBytes = 3 << 30 // 3 GiB = 75%
	writeCgroupDir(t, root, limitBytes, currentBytes, limitBytes*9/10, 0)

	c := NewCgroupMemoryCollector(newSilentLogger(), 50*time.Millisecond)
	c.cgroupRoot = root

	if err := c.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}

	snap, ok := c.Snapshot().(*CgroupMemorySnapshot)
	if !ok || snap == nil {
		t.Fatal("expected non-nil CgroupMemorySnapshot")
	}
	if len(snap.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(snap.Containers))
	}
	e := snap.Containers[0]
	if e.LimitBytes != limitBytes {
		t.Errorf("LimitBytes = %d, want %d", e.LimitBytes, uint64(limitBytes))
	}
	if e.CurrentBytes != currentBytes {
		t.Errorf("CurrentBytes = %d, want %d", e.CurrentBytes, uint64(currentBytes))
	}
	if e.UsedPct < 74.0 || e.UsedPct > 76.0 {
		t.Errorf("UsedPct = %.1f, want ~75", e.UsedPct)
	}
	if e.Pod == "" {
		t.Error("Pod should be non-empty (extracted from path)")
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
	root := t.TempDir()
	const limitBytes = 1 << 30                                                 // 1 GiB
	cgPath := writeCgroupDir(t, root, limitBytes, 700<<20, limitBytes*9/10, 0) // 700 MB initial

	c := NewCgroupMemoryCollector(newSilentLogger(), 10*time.Millisecond)
	c.cgroupRoot = root

	if err := c.poll(); err != nil {
		t.Fatal(err)
	}

	// Simulate memory growth to 800 MB.
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(cgPath, "memory.current"), []byte(fmt.Sprintf("%d\n", 800<<20)), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := c.poll(); err != nil {
		t.Fatal(err)
	}

	snap := c.Snapshot().(*CgroupMemorySnapshot)
	if len(snap.Containers) == 0 {
		t.Fatal("expected containers in snapshot")
	}
	if snap.Containers[0].GrowthRateBytesPerSec <= 0 {
		t.Errorf("GrowthRateBytesPerSec = %v, want > 0", snap.Containers[0].GrowthRateBytesPerSec)
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

func TestReadCgroupMemoryEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "memory.events")
	content := "low 0\nhigh 4\nmax 2\noom 1\noom_kill 1\noom_group_kill 0\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readCgroupMemoryEvents(path)
	cases := map[string]uint64{"low": 0, "high": 4, "max": 2, "oom": 1, "oom_kill": 1, "oom_group_kill": 0}
	for k, want := range cases {
		if got[k] != want {
			t.Errorf("events[%q] = %d, want %d", k, got[k], want)
		}
	}
}

func TestParseCgroupPod(t *testing.T) {
	cases := []struct {
		path      string
		wantPod   string
		wantEmpty bool
	}{
		{"/sys/fs/cgroup/kubepods/burstable/poda1b2c3d4/container-xyz", "poda1b2c3d4", false},
		{"/sys/fs/cgroup/kubepods/guaranteed/pod-foo-bar/ctr0", "pod-foo-bar", false},
		{"/sys/fs/cgroup/system.slice/docker-abc123.scope", "docker-abc123.scope", false},
	}
	for _, c := range cases {
		pod := parseCgroupPod(c.path)
		if pod == "" {
			t.Errorf("parseCgroupPod(%q) pod is empty", c.path)
		}
		if c.wantPod != "" && pod != c.wantPod {
			t.Errorf("parseCgroupPod(%q) = %q, want %q", c.path, pod, c.wantPod)
		}
	}
}
