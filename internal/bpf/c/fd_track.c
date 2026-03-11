// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lowplane contributors.
//
// fd_track.c — File descriptor open/close tracker.
//
// Hooks:
//   tracepoint/syscalls/sys_exit_openat → track FD opens (fd > 0)
//   tracepoint/syscalls/sys_exit_close  → track FD closes (ret == 0)
//
// Output: ring buffer of fd_event structs
//
// Detects FD leaks by tracking the delta of opens vs closes per PID.
// Userspace maintains a running counter and alerts on sustained growth.

#include "headers/kerno.h"

// Output ring buffer.
KERNO_RINGBUF(events);

// sys_exit_openat: the return value is the new FD (or negative errno).
SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret < 0)
        return 0;  // Failed open — ignore.

    struct fd_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = bpf_get_current_cgroup_id();
    e->pid          = pid_tgid >> 32;
    e->fd           = (__s32)ret;
    e->op           = FD_OP_OPEN;
    __builtin_memset(e->_pad, 0, sizeof(e->_pad));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// sys_exit_close: return value 0 means success.
SEC("tracepoint/syscalls/sys_exit_close")
int tracepoint_sys_exit_close(struct trace_event_raw_sys_exit *ctx)
{
    if (ctx->ret != 0)
        return 0;  // Failed close — ignore.

    struct fd_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = bpf_get_current_cgroup_id();
    e->pid          = pid_tgid >> 32;
    e->fd           = 0;  // We don't know which FD was closed from sys_exit.
    e->op           = FD_OP_CLOSE;
    __builtin_memset(e->_pad, 0, sizeof(e->_pad));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
