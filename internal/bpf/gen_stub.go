// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// This file provides placeholder types so `make build` works on a fresh
// clone without clang or libbpf installed.
//
// Build modes:
//   - default (`make build`): the `ebpf` tag is OFF, this stub compiles,
//     the bpf2go-generated `*_bpfel.go` files are excluded. No clang
//     required. The binary builds but cannot actually load BPF programs.
//   - real BPF (`make build-ebpf`): the `ebpf` tag is ON, this stub is
//     excluded, the generated files compile. Requires clang + libbpf.
//
// `make generate` post-processes each generated file's build tag to
// require `ebpf`, which is what makes the two modes mutually exclusive
// instead of duplicate-declaring on common architectures.

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
