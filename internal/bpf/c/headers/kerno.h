// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lowplane contributors.
//
// kerno.h — Shared definitions for all Kerno eBPF programs.
//
// Every event struct defined here MUST match the corresponding Go struct
// in the loader (internal/bpf/*.go) exactly — same field order, same sizes.
// Use explicit-width types (__u32, __u64, etc.) and pack where needed.

#ifndef __KERNO_H__
#define __KERNO_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ──────────────────────────────────────────────────────────────

#define TASK_COMM_LEN  16
#define MAX_ENTRIES    8192
#define RINGBUF_SIZE   (256 * 1024)  // 256 KB per ring buffer

// ─── Severity levels (matches Go Severity type) ────────────────────────────

#define SEVERITY_INFO     0
#define SEVERITY_WARNING  1
#define SEVERITY_CRITICAL 2

// ─── Event types (discriminator for union-style processing) ────────────────

#define EVENT_SYSCALL_LATENCY  1
#define EVENT_TCP_MONITOR      2
#define EVENT_OOM_KILL         3
#define EVENT_DISK_IO          4
#define EVENT_SCHED_DELAY      5
#define EVENT_FD_TRACK         6
#define EVENT_FILE_AUDIT       7

// ─── Syscall Latency Event ─────────────────────────────────────────────────

struct syscall_event {
    __u64 timestamp_ns;
    __u64 latency_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 tid;
    __u32 syscall_nr;
    __u32 ret;
    char  comm[TASK_COMM_LEN];
};

// ─── TCP Monitor Event ─────────────────────────────────────────────────────

// TCP event subtypes.
#define TCP_EVENT_CONNECT     1
#define TCP_EVENT_CLOSE       2
#define TCP_EVENT_RETRANSMIT  3
#define TCP_EVENT_RTT         4

struct tcp_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 saddr;    // IPv4 source address (network byte order)
    __u32 daddr;    // IPv4 destination address (network byte order)
    __u16 sport;
    __u16 dport;
    __u16 family;   // AF_INET or AF_INET6
    __u8  event_type;  // TCP_EVENT_* subtype
    __u8  state;       // TCP state for state change events
    __u32 rtt_us;      // smoothed RTT in microseconds (for RTT events)
    __u32 retransmits; // total retransmit count
    char  comm[TASK_COMM_LEN];
};

// ─── OOM Kill Event ────────────────────────────────────────────────────────

struct oom_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u64 total_pages;
    __u64 rss_pages;
    __u32 pid;
    __u32 triggered_pid; // PID that triggered the OOM killer
    __s32 oom_score;
    __u32 _pad;
    char  comm[TASK_COMM_LEN];
};

// ─── Disk I/O Event ────────────────────────────────────────────────────────

struct disk_event {
    __u64 timestamp_ns;
    __u64 latency_ns;
    __u64 sector;
    __u32 dev;          // device number (MKDEV)
    __u32 nr_bytes;
    __u8  op;           // 'R' = read, 'W' = write, 'S' = sync
    __u8  _pad[7];
};

// ─── Scheduler Delay Event ─────────────────────────────────────────────────

struct sched_event {
    __u64 timestamp_ns;
    __u64 runq_delay_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 cpu;
    char  comm[TASK_COMM_LEN];
};

// ─── File Descriptor Track Event ───────────────────────────────────────────

#define FD_OP_OPEN   1
#define FD_OP_CLOSE  2

struct fd_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __s32 fd;
    __u8  op;     // FD_OP_OPEN or FD_OP_CLOSE
    __u8  _pad[7];
    char  comm[TASK_COMM_LEN];
};

// ─── File Audit Event ──────────────────────────────────────────────────────

#define MAX_FILENAME_LEN 256

struct file_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 uid;
    __u32 flags;
    __u32 _pad;
    char  comm[TASK_COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
};

// ─── Helper macros ─────────────────────────────────────────────────────────

// Declare a BPF ring buffer map with the given name.
#define KERNO_RINGBUF(name) \
    struct { \
        __uint(type, BPF_MAP_TYPE_RINGBUF); \
        __uint(max_entries, RINGBUF_SIZE); \
    } name SEC(".maps")

// Declare a BPF hash map.
#define KERNO_HASH(name, key_type, val_type, max) \
    struct { \
        __uint(type, BPF_MAP_TYPE_HASH); \
        __uint(max_entries, max); \
        __type(key, key_type); \
        __type(value, val_type); \
    } name SEC(".maps")

#endif // __KERNO_H__
