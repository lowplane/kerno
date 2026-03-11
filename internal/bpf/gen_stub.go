// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

// This file provides placeholder types for development without running bpf2go.
// When you run `go generate ./internal/bpf/...`, bpf2go creates the real
// *_bpfel.go files that embed compiled eBPF bytecode. Those files will
// override these stubs via the build tag.
//
// To build with real eBPF support:
//   1. Install clang + libbpf-dev
//   2. Run: make generate
//   3. Run: make build

//go:build !ebpf

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// ─── Syscall Latency stubs ──────────────────────────────────────────────────

type syscallLatencyObjects struct {
	TracepointSysEnter *ebpf.Program `ebpf:"tracepoint_sys_enter"`
	TracepointSysExit  *ebpf.Program `ebpf:"tracepoint_sys_exit"`
	Events             *ebpf.Map     `ebpf:"events"`
}

func loadSyscallLatencyObjects(obj *syscallLatencyObjects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF programs not compiled; run 'make generate' first")
}

func (o *syscallLatencyObjects) Close() error { return nil }

// ─── TCP Monitor stubs ──────────────────────────────────────────────────────

type tcpMonitorObjects struct {
	TracepointTcpRetransmit    *ebpf.Program `ebpf:"tracepoint_tcp_retransmit"`
	TracepointInetSockSetState *ebpf.Program `ebpf:"tracepoint_inet_sock_set_state"`
	Events                     *ebpf.Map     `ebpf:"events"`
}

func loadTcpMonitorObjects(obj *tcpMonitorObjects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF programs not compiled; run 'make generate' first")
}

func (o *tcpMonitorObjects) Close() error { return nil }

// ─── OOM Track stubs ────────────────────────────────────────────────────────

type oomTrackObjects struct {
	KprobeOomKill *ebpf.Program `ebpf:"kprobe_oom_kill"`
	Events        *ebpf.Map     `ebpf:"events"`
}

func loadOomTrackObjects(obj *oomTrackObjects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF programs not compiled; run 'make generate' first")
}

func (o *oomTrackObjects) Close() error { return nil }

// ─── Disk I/O stubs ─────────────────────────────────────────────────────────

type diskIOObjects struct {
	TracepointBlockRqIssue    *ebpf.Program `ebpf:"tracepoint_block_rq_issue"`
	TracepointBlockRqComplete *ebpf.Program `ebpf:"tracepoint_block_rq_complete"`
	Events                    *ebpf.Map     `ebpf:"events"`
}

func loadDiskIOObjects(obj *diskIOObjects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF programs not compiled; run 'make generate' first")
}

func (o *diskIOObjects) Close() error { return nil }

// ─── Sched Delay stubs ──────────────────────────────────────────────────────

type schedDelayObjects struct {
	TracepointSchedWakeup *ebpf.Program `ebpf:"tracepoint_sched_wakeup"`
	TracepointSchedSwitch *ebpf.Program `ebpf:"tracepoint_sched_switch"`
	Events                *ebpf.Map     `ebpf:"events"`
}

func loadSchedDelayObjects(obj *schedDelayObjects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF programs not compiled; run 'make generate' first")
}

func (o *schedDelayObjects) Close() error { return nil }

// ─── FD Track stubs ─────────────────────────────────────────────────────────

type fdTrackObjects struct {
	TracepointSysExitOpenat *ebpf.Program `ebpf:"tracepoint_sys_exit_openat"`
	TracepointSysExitClose  *ebpf.Program `ebpf:"tracepoint_sys_exit_close"`
	Events                  *ebpf.Map     `ebpf:"events"`
}

func loadFdTrackObjects(obj *fdTrackObjects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF programs not compiled; run 'make generate' first")
}

func (o *fdTrackObjects) Close() error { return nil }
