// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"testing"
)

// fakeCollector implements Collector for testing.
type fakeCollector struct {
	name    string
	started bool
	stopped bool
	snap    interface{}
	startFn func() error
}

func (f *fakeCollector) Name() string { return f.name }

func (f *fakeCollector) Start(_ context.Context) error {
	f.started = true
	if f.startFn != nil {
		return f.startFn()
	}
	return nil
}

func (f *fakeCollector) Stop() { f.stopped = true }

func (f *fakeCollector) Snapshot() interface{} { return f.snap }

// ─── Registry Tests ─────────────────────────────────────────────────────────

func newTestRegistry() *Registry {
	return NewRegistry(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
}

func TestRegistryRegister(t *testing.T) {
	r := newTestRegistry()
	c := &fakeCollector{name: "test"}

	if err := r.Register(c); err != nil {
		t.Fatalf("Register() unexpected error: %v", err)
	}

	if got := r.Get("test"); got != c {
		t.Errorf("Get('test') returned wrong collector")
	}
}

func TestRegistryRegisterDuplicate(t *testing.T) {
	r := newTestRegistry()
	c1 := &fakeCollector{name: "dup"}
	c2 := &fakeCollector{name: "dup"}

	if err := r.Register(c1); err != nil {
		t.Fatalf("Register(c1) unexpected error: %v", err)
	}

	err := r.Register(c2)
	if err == nil {
		t.Error("Register(c2) expected error for duplicate, got nil")
	}
}

func TestRegistryGetNotFound(t *testing.T) {
	r := newTestRegistry()
	if got := r.Get("nonexistent"); got != nil {
		t.Errorf("Get('nonexistent') = %v, want nil", got)
	}
}

func TestRegistryNames(t *testing.T) {
	r := newTestRegistry()
	for _, name := range []string{"alpha", "bravo", "charlie"} {
		if err := r.Register(&fakeCollector{name: name}); err != nil {
			t.Fatalf("Register(%q): %v", name, err)
		}
	}

	names := r.Names()
	sort.Strings(names)

	want := []string{"alpha", "bravo", "charlie"}
	if len(names) != len(want) {
		t.Fatalf("Names() returned %d names, want %d", len(names), len(want))
	}
	for i, n := range names {
		if n != want[i] {
			t.Errorf("Names()[%d] = %q, want %q", i, n, want[i])
		}
	}
}

func TestRegistryStartAll(t *testing.T) {
	r := newTestRegistry()
	collectors := []*fakeCollector{
		{name: "a"},
		{name: "b"},
	}
	for _, c := range collectors {
		if err := r.Register(c); err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.Background()
	if err := r.StartAll(ctx); err != nil {
		t.Fatalf("StartAll() unexpected error: %v", err)
	}

	for _, c := range collectors {
		if !c.started {
			t.Errorf("collector %q was not started", c.name)
		}
	}
}

func TestRegistryStopAll(t *testing.T) {
	r := newTestRegistry()
	collectors := []*fakeCollector{
		{name: "x"},
		{name: "y"},
	}
	for _, c := range collectors {
		if err := r.Register(c); err != nil {
			t.Fatal(err)
		}
	}

	r.StopAll()

	for _, c := range collectors {
		if !c.stopped {
			t.Errorf("collector %q was not stopped", c.name)
		}
	}
}

func TestRegistryStartAllError(t *testing.T) {
	r := newTestRegistry()
	bad := &fakeCollector{
		name: "fail",
		startFn: func() error {
			return context.DeadlineExceeded
		},
	}
	if err := r.Register(bad); err != nil {
		t.Fatal(err)
	}

	err := r.StartAll(context.Background())
	if err == nil {
		t.Error("StartAll() expected error, got nil")
	}
}

func TestRegistrySignals(t *testing.T) {
	r := newTestRegistry()

	syscallSnap := &SyscallSnapshot{TotalCount: 1000}
	tcpSnap := &TCPSnapshot{ActiveConnections: 5}
	oomSnap := &OOMSnapshot{Count: 2}

	collectors := []Collector{
		&fakeCollector{name: "syscall", snap: syscallSnap},
		&fakeCollector{name: "tcp", snap: tcpSnap},
		&fakeCollector{name: "oom", snap: oomSnap},
		&fakeCollector{name: "empty", snap: nil}, // nil snapshot
	}
	for _, c := range collectors {
		if err := r.Register(c); err != nil {
			t.Fatal(err)
		}
	}

	signals := r.Signals(30_000_000_000) // 30s

	if signals.Syscall == nil || signals.Syscall.TotalCount != 1000 {
		t.Errorf("Signals.Syscall = %+v, want TotalCount=1000", signals.Syscall)
	}
	if signals.TCP == nil || signals.TCP.ActiveConnections != 5 {
		t.Errorf("Signals.TCP = %+v, want ActiveConnections=5", signals.TCP)
	}
	if signals.OOM == nil || signals.OOM.Count != 2 {
		t.Errorf("Signals.OOM = %+v, want Count=2", signals.OOM)
	}
	if signals.DiskIO != nil {
		t.Errorf("Signals.DiskIO should be nil, got %+v", signals.DiskIO)
	}
	if signals.Sched != nil {
		t.Errorf("Signals.Sched should be nil, got %+v", signals.Sched)
	}
	if signals.FD != nil {
		t.Errorf("Signals.FD should be nil, got %+v", signals.FD)
	}
}
