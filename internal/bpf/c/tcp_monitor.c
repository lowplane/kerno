// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Optiqor contributors.
//
// tcp_monitor.c — Traces TCP retransmits, connection state changes, and RTT.
//
// Hooks:
//   tracepoint/tcp/tcp_retransmit_skb     → retransmit events
//   tracepoint/sock/inet_sock_set_state   → connection lifecycle
//
// Output: ring buffer of tcp_event structs

#include "headers/kerno.h"

// Linux socket address family — vmlinux.h does not include <sys/socket.h>.
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

// Output ring buffer.
KERNO_RINGBUF(events);

// Force BTF emission of struct tcp_event so bpf2go can extract it.
const struct tcp_event *_force_btf_tcp_event __attribute__((used));

// ─── TCP retransmit tracepoint ──────────────────────────────────────────────

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tracepoint_tcp_retransmit(struct trace_event_raw_tcp_retransmit_skb *ctx)
{
    // Only handle IPv4 for now.
    if (ctx->family != AF_INET)
        return 0;

    struct tcp_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = bpf_get_current_cgroup_id();
    e->pid          = bpf_get_current_pid_tgid() >> 32;

    // Read IPv4 addresses from the tracepoint context.
    // Tracepoint ctx arrays must be read via the helper — direct memcpy
    // from ctx is rejected by the verifier on stricter kernels.
    bpf_probe_read_kernel(&e->saddr, 4, ctx->saddr);
    bpf_probe_read_kernel(&e->daddr, 4, ctx->daddr);
    e->sport        = ctx->sport;
    e->dport        = ctx->dport;
    e->family       = ctx->family;
    e->event_type   = TCP_EVENT_RETRANSMIT;
    e->state        = (__u8)ctx->state;
    e->rtt_us       = 0;
    e->retransmits  = 0;  // Counter maintained in userspace.

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── TCP state change tracepoint ────────────────────────────────────────────

SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // Only handle IPv4 TCP connections.
    if (ctx->family != AF_INET)
        return 0;

    __u8 event_type;
    // Determine event type from state transition.
    // TCP_ESTABLISHED = 1, TCP_CLOSE = 7
    if (ctx->newstate == 1) {
        event_type = TCP_EVENT_CONNECT;
    } else if (ctx->newstate == 7) {
        event_type = TCP_EVENT_CLOSE;
    } else {
        return 0;  // Skip intermediate states.
    }

    struct tcp_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = bpf_get_current_cgroup_id();
    e->pid          = bpf_get_current_pid_tgid() >> 32;

    // Tracepoint ctx arrays must be read via the helper — direct memcpy
    // from ctx is rejected by the verifier on stricter kernels.
    bpf_probe_read_kernel(&e->saddr, 4, ctx->saddr);
    bpf_probe_read_kernel(&e->daddr, 4, ctx->daddr);
    e->sport        = ctx->sport;
    e->dport        = ctx->dport;
    e->family       = ctx->family;
    e->event_type   = event_type;
    e->state        = (__u8)ctx->newstate;
    e->rtt_us       = 0;
    e->retransmits  = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
