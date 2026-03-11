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

#ifndef bool
typedef _Bool bool;
#define true  1
#define false 0
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

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
