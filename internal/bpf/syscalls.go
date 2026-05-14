// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

import "fmt"

// SyscallName returns the name for a Linux syscall number on amd64.
// Covers the most common syscalls; unknown numbers return "syscall_NR".
//
// This is a curated subset (the syscalls most often implicated in
// performance and reliability incidents). For a complete map, generate
// from the kernel's syscalls.tbl at build time.
func SyscallName(nr uint32) string {
	if name, ok := syscallNames[nr]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}

var syscallNames = map[uint32]string{
	0: "read", 1: "write", 2: "open", 3: "close",
	4: "stat", 5: "fstat", 6: "lstat", 7: "poll",
	8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
	12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
	16: "ioctl", 17: "pread64", 18: "pwrite64",
	19: "readv", 20: "writev", 21: "access",
	22: "pipe", 23: "select", 24: "sched_yield",
	32: "dup", 33: "dup2",
	39: "getpid", 41: "socket", 42: "connect", 43: "accept",
	44: "sendto", 45: "recvfrom", 46: "sendmsg", 47: "recvmsg",
	48: "shutdown", 49: "bind", 50: "listen",
	56: "clone", 57: "fork", 58: "vfork", 59: "execve",
	60: "exit", 61: "wait4", 62: "kill",
	72: "fcntl", 73: "flock", 74: "fsync", 75: "fdatasync",
	77: "ftruncate", 78: "getdents",
	79: "getcwd", 80: "chdir", 82: "rename",
	83: "mkdir", 84: "rmdir", 85: "creat", 86: "link", 87: "unlink",
	89: "readlink", 90: "chmod", 92: "chown",
	137: "statfs", 186: "gettid",
	202: "futex", 217: "getdents64",
	231: "exit_group", 232: "epoll_wait",
	257: "openat", 262: "newfstatat",
	268: "fchmodat", 280: "utimensat",
	288: "accept4", 290: "sendmmsg",
	302: "prlimit64", 318: "getrandom",
	332: "statx",
	435: "clone3",
}

// IsSyscallError returns true if the syscall return value indicates an
// error. On Linux, syscall returns in the range [-4095, -1] are errors;
// when stored in a uint32 those become 0xFFFFF001..0xFFFFFFFF.
func IsSyscallError(ret uint32) bool {
	return ret >= 0xFFFFF001
}

// blockingSyscalls is the set of syscall numbers (amd64) that voluntarily
// block waiting for an event. Their latency does not represent kernel
// or hardware slowness — it represents how long the userspace caller
// chose to wait. The doctor's syscall_latency_high rule must exclude
// these or it would flag every idle process as critically slow.
//
// Each of these can also return non-fatal "errors" (EAGAIN, ETIMEDOUT,
// ECHILD) as part of normal operation, so they're also excluded from
// the syscall_error_rate rule.
var blockingSyscalls = map[uint32]bool{
	7:   true, // poll
	23:  true, // select
	61:  true, // wait4
	35:  true, // nanosleep
	34:  true, // pause
	232: true, // epoll_wait
	202: true, // futex
	247: true, // waitid
	270: true, // pselect6
	271: true, // ppoll
	281: true, // epoll_pwait
	441: true, // epoll_pwait2
	43:  true, // accept
	288: true, // accept4
}

// IsBlockingSyscall reports whether a syscall is one of the voluntary
// blocking ones (epoll_wait, futex, wait4, ...). The doctor uses this
// to suppress false positives from idle processes.
func IsBlockingSyscall(nr uint32) bool {
	return blockingSyscalls[nr]
}
