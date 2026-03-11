// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lowplane contributors.
//
// sched_delay.c — CPU run queue latency tracer (runqlat).
//
// Hooks:
//   tracepoint/sched/sched_wakeup  → record wakeup timestamp
//   tracepoint/sched/sched_switch  → compute run queue delay
//
// Output: ring buffer of sched_event structs
//
// Measures the time a runnable task waits in the CPU run queue before
// being scheduled. High values indicate CPU contention.

#include "headers/kerno.h"

// Key: pid → Value: wakeup timestamp.
KERNO_HASH(wakeup_ts, __u32, __u64, MAX_ENTRIES);

// Output ring buffer.
KERNO_RINGBUF(events);

SEC("tracepoint/sched/sched_wakeup")
int tracepoint_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    __u32 pid = ctx->pid;
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&wakeup_ts, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int tracepoint_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u32 pid = ctx->next_pid;

    __u64 *ts = bpf_map_lookup_elem(&wakeup_ts, &pid);
    if (!ts)
        return 0;

    __u64 delay = bpf_ktime_get_ns() - *ts;
    bpf_map_delete_elem(&wakeup_ts, &pid);

    // Filter sub-microsecond noise.
    if (delay < 1000)
        return 0;

    struct sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns  = bpf_ktime_get_ns();
    e->runq_delay_ns = delay;
    e->cgroup_id     = bpf_get_current_cgroup_id();
    e->pid           = pid;
    e->cpu           = bpf_get_smp_processor_id();

    // Read comm from next task context.
    __builtin_memcpy(e->comm, ctx->next_comm, TASK_COMM_LEN);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
