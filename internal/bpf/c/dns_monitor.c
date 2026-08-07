// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Optiqor contributors.
//
// dns_monitor.c - Traces UDP/53 DNS sends and receives per pod/process.
//
// Hooks:
//   tracepoint/syscalls/sys_enter_sendmsg  -> DNS request events
//   tracepoint/syscalls/sys_enter_recvmsg  -> DNS response events
//
// Filter: destination (send) or source (recv) port == 53 only.
// Output: ring buffer of dns_event structs.

#include "headers/kerno.h"

#ifndef AF_INET
#define AF_INET 2
#endif

// Output ring buffer.
KERNO_RINGBUF(dns_events);

// In-flight request tracking: key = (pid << 16 | query_id), value = send timestamp_ns.
KERNO_HASH(dns_inflight, __u64, __u64, 4096);

// Force BTF emission so bpf2go can extract the struct.
const struct dns_event *_force_btf_dns_event __attribute__((used));

// Helper: read query_id (first 2 bytes of UDP payload = DNS transaction ID).
static __always_inline __u16 read_query_id(const struct msghdr *msg)
{
    __u8 buf[2] = {0, 0};
    struct iovec iov = {};

    // Read the first iovec from userspace.
    if (bpf_probe_read_user(&iov, sizeof(iov), BPF_CORE_READ(msg, msg_iter.iov)) != 0)
        return 0;
    if (iov.iov_len < 2)
        return 0;

    bpf_probe_read_user(buf, 2, iov.iov_base);
    return ((__u16)buf[0] << 8) | buf[1];
}

// Helper: extract destination IPv4 address and port from sockaddr_in.
static __always_inline int read_dest(const struct msghdr *msg,
                                      __u32 *daddr, __u16 *dport)
{
    void *name_ptr = NULL;
    __u32 name_len = 0;
    struct sockaddr_in sin = {};

    bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr),
                          &msg->msg_name);
    bpf_probe_read_kernel(&name_len, sizeof(name_len),
                          &msg->msg_namelen);

    if (!name_ptr || name_len < sizeof(sin))
        return -1;

    bpf_probe_read_user(&sin, sizeof(sin), name_ptr);
    if (sin.sin_family != AF_INET)
        return -1;

    *daddr = sin.sin_addr.s_addr;
    *dport = __builtin_bswap16(sin.sin_port);
    return 0;
}

// --- sys_enter_sendmsg -------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint_sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    // ctx->args[1] is the msghdr pointer.
    struct msghdr *msg = (struct msghdr *)(long)ctx->args[1];
    if (!msg)
        return 0;

    __u32 daddr = 0;
    __u16 dport = 0;
    if (read_dest(msg, &daddr, &dport) != 0)
        return 0;

    // Filter: only DNS (port 53).
    if (dport != 53)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u16 qid = read_query_id(msg);

    // Record send timestamp for latency calculation.
    __u64 inflight_key = ((pid_tgid >> 32) << 16) | qid;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&dns_inflight, &inflight_key, &now, BPF_ANY);

    struct dns_event *e = bpf_ringbuf_reserve(&dns_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = now;
    e->cgroup_id    = bpf_get_current_cgroup_id();
    e->pid          = pid_tgid >> 32;
    e->saddr        = 0;  // source filled in userspace from socket
    e->daddr        = daddr;
    e->sport        = 0;
    e->dport        = dport;
    e->query_id     = qid;
    e->event_type   = DNS_EVENT_SEND;
    e->_pad         = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --- sys_enter_recvmsg -------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tracepoint_sys_enter_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct msghdr *msg = (struct msghdr *)(long)ctx->args[1];
    if (!msg)
        return 0;

    __u32 saddr = 0;
    __u16 sport = 0;
    if (read_dest(msg, &saddr, &sport) != 0)
        return 0;

    // Only care about responses from port 53.
    if (sport != 53)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u16 qid = read_query_id(msg);

    __u64 inflight_key = ((pid_tgid >> 32) << 16) | qid;
    __u64 *send_ns = bpf_map_lookup_elem(&dns_inflight, &inflight_key);
    __u64 now = bpf_ktime_get_ns();

    if (send_ns)
        bpf_map_delete_elem(&dns_inflight, &inflight_key);

    struct dns_event *e = bpf_ringbuf_reserve(&dns_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = send_ns ? *send_ns : now;
    e->cgroup_id    = bpf_get_current_cgroup_id();
    e->pid          = pid_tgid >> 32;
    e->saddr        = saddr;
    e->daddr        = 0;
    e->sport        = sport;
    e->dport        = 0;
    e->query_id     = qid;
    e->event_type   = DNS_EVENT_RECV;
    e->_pad         = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
