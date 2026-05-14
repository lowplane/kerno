// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Optiqor contributors.
//
// disk_io.c — Block I/O latency tracer.
//
// Hooks:
//   tracepoint/block/block_rq_issue    → record issue timestamp
//   tracepoint/block/block_rq_complete → compute latency delta
//
// Output: ring buffer of disk_event structs

#include "headers/kerno.h"

// Key: sector number → Value: issue timestamp.
KERNO_HASH(io_start, __u64, __u64, MAX_ENTRIES);

// Output ring buffer.
KERNO_RINGBUF(events);

// Force BTF emission of struct disk_event so bpf2go can extract it.
const struct disk_event *_force_btf_disk_event __attribute__((used));

SEC("tracepoint/block/block_rq_issue")
int tracepoint_block_rq_issue(struct trace_event_raw_block_rq *ctx)
{
    __u64 sector = ctx->sector;
    if (sector == 0)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&io_start, &sector, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int tracepoint_block_rq_complete(struct trace_event_raw_block_rq_completion *ctx)
{
    __u64 sector = ctx->sector;

    __u64 *start_ts = bpf_map_lookup_elem(&io_start, &sector);
    if (!start_ts)
        return 0;

    __u64 latency = bpf_ktime_get_ns() - *start_ts;
    bpf_map_delete_elem(&io_start, &sector);

    struct disk_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->latency_ns   = latency;
    e->sector        = sector;
    e->dev           = (__u32)ctx->dev;
    e->nr_bytes      = ctx->nr_sector * 512;
    e->pid           = (__u32)(bpf_get_current_pid_tgid() >> 32);

    // rwbs[0] is the primary op (R/W/D); subsequent positions hold flag
    // chars (S=sync, F=FUA, A=ahead, M=meta). Promote fsync'd writes to
    // op='S' so the doctor's SyncLatency tracker actually sees them.
    //
    // The verifier disallows variable-index reads off a tracepoint ctx
    // pointer, so copy rwbs into a local buffer via the helper and
    // inspect that. With a stack-resident buffer, indexed reads are fine.
    char rwbs[8] = {};
    bpf_probe_read_kernel(rwbs, sizeof(rwbs), ctx->rwbs);
    char op = rwbs[0];
    if (rwbs[1] == 'S' || rwbs[1] == 'F' ||
        rwbs[2] == 'S' || rwbs[2] == 'F' ||
        rwbs[3] == 'S' || rwbs[3] == 'F') {
        op = 'S';
    }
    e->op = op;

    // Zero padding.
    __builtin_memset(e->_pad, 0, sizeof(e->_pad));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
