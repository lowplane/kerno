// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lowplane contributors.
//
// syscall_latency.c — Measures the time between syscall entry and exit.
//
// Hook: tracepoint/raw_syscalls/sys_enter + sys_exit
// Output: ring buffer of syscall_event structs (pid, comm, syscall_nr, latency_ns)

#include "headers/kerno.h"

// Temporary storage: pid → entry timestamp.
KERNO_HASH(syscall_start, __u64, __u64, MAX_ENTRIES);

// Output ring buffer.
KERNO_RINGBUF(events);

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&syscall_start, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u64 *start_ts = bpf_map_lookup_elem(&syscall_start, &pid_tgid);
    if (!start_ts)
        return 0;

    __u64 latency = bpf_ktime_get_ns() - *start_ts;
    bpf_map_delete_elem(&syscall_start, &pid_tgid);

    // Filter out sub-microsecond noise.
    if (latency < 1000)
        return 0;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->latency_ns   = latency;
    e->cgroup_id    = bpf_get_current_cgroup_id();
    e->pid          = pid_tgid >> 32;
    e->tid          = (__u32)pid_tgid;
    e->syscall_nr   = (__u32)ctx->id;
    e->ret          = (__u32)ctx->ret;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
