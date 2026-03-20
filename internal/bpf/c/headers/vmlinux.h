/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * vmlinux.h — Minimal BTF-generated kernel type definitions for Kerno.
 *
 * In production, regenerate this from your running kernel:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *
 * This minimal version provides only the types required by Kerno's
 * eBPF programs, enabling compilation without a full kernel BTF dump.
 * It is suitable for CI and development on machines without BTF support.
 *
 * When targeting a specific kernel, replace this file with the full
 * output of bpftool for maximum CO-RE portability.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

// ─── Basic types ────────────────────────────────────────────────────────────

typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;
typedef signed char         __s8;
typedef signed short        __s16;
typedef signed int          __s32;
typedef signed long long    __s64;

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8  s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

typedef int    pid_t;
typedef __u32  uid_t;
typedef __u32  gid_t;
typedef __u64  dev_t;
typedef long   ssize_t;
typedef unsigned long size_t;

// Network byte-order types (needed by bpf_helper_defs.h).
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;
typedef __u16 __sum16;

#ifndef bool
typedef _Bool bool;
#define true  1
#define false 0
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

// ─── BPF constants ──────────────────────────────────────────────────────────

// Map types used by Kerno programs.
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC         = 0,
    BPF_MAP_TYPE_HASH           = 1,
    BPF_MAP_TYPE_ARRAY          = 2,
    BPF_MAP_TYPE_PROG_ARRAY     = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH    = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY   = 6,
    BPF_MAP_TYPE_STACK_TRACE    = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY   = 8,
    BPF_MAP_TYPE_LRU_HASH       = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE       = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS  = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS   = 13,
    BPF_MAP_TYPE_DEVMAP         = 14,
    BPF_MAP_TYPE_SOCKMAP         = 15,
    BPF_MAP_TYPE_CPUMAP         = 16,
    BPF_MAP_TYPE_XSKMAP         = 17,
    BPF_MAP_TYPE_SOCKHASH       = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE          = 22,
    BPF_MAP_TYPE_STACK          = 23,
    BPF_MAP_TYPE_SK_STORAGE     = 24,
    BPF_MAP_TYPE_DEVMAP_HASH    = 25,
    BPF_MAP_TYPE_STRUCT_OPS     = 26,
    BPF_MAP_TYPE_RINGBUF        = 27,
    BPF_MAP_TYPE_INODE_STORAGE  = 28,
    BPF_MAP_TYPE_TASK_STORAGE   = 29,
};

// BPF map update flags.
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

// ─── pt_regs (needed by bpf_tracing.h for kprobes) ─────────────────────────

struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

// ─── Network ────────────────────────────────────────────────────────────────

#define AF_INET   2
#define AF_INET6  10

// ─── Scheduler / task_struct ────────────────────────────────────────────────

#define TASK_COMM_LEN 16

struct task_struct {
    int pid;
    int tgid;
    char comm[TASK_COMM_LEN];
};

// ─── Tracepoint arguments ───────────────────────────────────────────────────

// raw_syscalls/sys_enter
struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long id;            // syscall number
    unsigned long args[6];
};

// raw_syscalls/sys_exit
struct trace_event_raw_sys_exit {
    unsigned long long unused;
    long id;            // syscall number
    long ret;           // return value
};

// sched/sched_wakeup and sched_wakeup_new
struct trace_event_raw_sched_wakeup_template {
    unsigned long long unused;
    char comm[TASK_COMM_LEN];
    pid_t pid;
    int prio;
    int success;
    int target_cpu;
};

// sched/sched_switch
struct trace_event_raw_sched_switch {
    unsigned long long unused;
    char prev_comm[TASK_COMM_LEN];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[TASK_COMM_LEN];
    pid_t next_pid;
    int next_prio;
};

// block/block_rq_issue & block_rq_complete
struct trace_event_raw_block_rq_completion {
    unsigned long long unused;
    dev_t dev;
    __u64 sector;
    unsigned int nr_sector;
    int error;
    char rwbs[8];
};

struct trace_event_raw_block_rq_issue {
    unsigned long long unused;
    dev_t dev;
    __u64 sector;
    unsigned int nr_sector;
    unsigned int bytes;
    char rwbs[8];
    char comm[TASK_COMM_LEN];
};

// ─── Network / TCP structs ──────────────────────────────────────────────────

struct sock_common {
    union {
        struct {
            __u32 skc_daddr;
            __u32 skc_rcv_saddr;
        };
    };
    union {
        unsigned int skc_hash;
        __u16 skc_u16hashes[2];
    };
    union {
        struct {
            __u16 skc_dport;
            __u16 skc_num;
        };
    };
    short unsigned int skc_family;
    volatile unsigned char skc_state;
};

struct sock {
    struct sock_common __sk_common;
};

struct inet_sock {
    struct sock sk;
    __u16 inet_sport;
};

struct tcp_sock {
    struct inet_sock inet_conn;
    __u32 srtt_us;           // smoothed round-trip time << 3
    __u32 mdev_us;
    __u32 total_retrans;
};

// tcp/tcp_retransmit_skb tracepoint
struct trace_event_raw_tcp_retransmit_skb {
    unsigned long long unused;
    const void *skbaddr;
    const void *skaddr;
    int state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
};

// sock/inet_sock_set_state tracepoint
struct trace_event_raw_inet_sock_set_state {
    unsigned long long unused;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
};

// ─── OOM types ──────────────────────────────────────────────────────────────

struct oom_control {
    struct task_struct *chosen;
    long chosen_points;
    unsigned long totalpages;
};

// ─── VFS / file types ───────────────────────────────────────────────────────

struct qstr {
    unsigned int hash;
    unsigned int len;
    const unsigned char *name;
};

struct dentry {
    struct qstr d_name;
    struct dentry *d_parent;
};

struct path {
    void *mnt;
    struct dentry *dentry;
};

struct file {
    struct path f_path;
    unsigned int f_flags;
};

#pragma clang attribute pop

#endif // __VMLINUX_H__
