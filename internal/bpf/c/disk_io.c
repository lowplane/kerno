// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lowplane contributors.
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

SEC("tracepoint/block/block_rq_issue")
int tracepoint_block_rq_issue(struct trace_event_raw_block_rq_issue *ctx)
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
    e->op            = ctx->rwbs[0];  // 'R', 'W', 'S', etc.

    // Zero padding.
    __builtin_memset(e->_pad, 0, sizeof(e->_pad));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
