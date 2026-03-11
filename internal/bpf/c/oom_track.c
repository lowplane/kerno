// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lowplane contributors.
//
// oom_track.c — Captures OOM kill events with full context.
//
// Hook: kprobe/oom_kill_process (no tracepoint available for OOM kill)
// Output: ring buffer of oom_event structs
//
// Note: We use kprobe because there is no stable tracepoint for the OOM
// killer path. The function signature is stable across kernel 5.4–6.x.

#include "headers/kerno.h"

// Output ring buffer.
KERNO_RINGBUF(events);

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(kprobe_oom_kill, struct oom_control *oc, const char *message)
{
    struct task_struct *victim;

    victim = BPF_CORE_READ(oc, chosen);
    if (!victim)
        return 0;

    struct oom_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns  = bpf_ktime_get_ns();
    e->cgroup_id     = bpf_get_current_cgroup_id();
    e->total_pages   = BPF_CORE_READ(oc, totalpages);
    e->rss_pages     = 0;  // Filled in userspace from /proc.
    e->pid           = BPF_CORE_READ(victim, tgid);
    e->triggered_pid = bpf_get_current_pid_tgid() >> 32;
    e->oom_score     = (__s32)BPF_CORE_READ(oc, chosen_points);
    e->_pad          = 0;

    BPF_CORE_READ_STR_INTO(&e->comm, victim, comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
