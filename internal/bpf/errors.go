// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"fmt"
	"strings"
)

// LoadError represents an eBPF program load failure with additional context.
type LoadError struct {
	Program string // Program name (e.g., "syscall_latency")
	Err     error  // Underlying error
	Hint    string // User-facing hint on how to fix
}

// Error implements the error interface.
func (e *LoadError) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("%s: %v (hint: %s)", e.Program, e.Err, e.Hint)
	}
	return fmt.Sprintf("%s: %v", e.Program, e.Err)
}

// Unwrap returns the underlying error.
func (e *LoadError) Unwrap() error {
	return e.Err
}

// WrapLoadError wraps an eBPF load error with program context and a helpful hint.
func WrapLoadError(program string, err error) error {
	if err == nil {
		return nil
	}

	hint := classifyLoadError(err)
	return &LoadError{
		Program: program,
		Err:     err,
		Hint:    hint,
	}
}

// classifyLoadError analyzes an error and returns a user-friendly fix hint.
func classifyLoadError(err error) string {
	if err == nil {
		return ""
	}

	msg := strings.ToLower(err.Error())

	switch {
	case strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied"):
		return "run with sudo or grant CAP_BPF+CAP_PERFMON+CAP_SYS_ADMIN capabilities"

	case strings.Contains(msg, "memlock") || strings.Contains(msg, "rlimit"):
		return "increase memlock limit: ulimit -l unlimited (or run as root)"

	case strings.Contains(msg, "btf") && strings.Contains(msg, "not found"):
		return "kernel needs CONFIG_DEBUG_INFO_BTF=y (requires kernel 5.8+)"

	case strings.Contains(msg, "vmlinux"):
		return "missing /sys/kernel/btf/vmlinux — kernel must be compiled with BTF support"

	case strings.Contains(msg, "verifier") || strings.Contains(msg, "invalid"):
		return "BPF verifier rejected the program — may need newer kernel or different approach"

	case strings.Contains(msg, "no such file") && strings.Contains(msg, "tracepoint"):
		return "tracepoint not available on this kernel — try kernel 5.10+ or file an issue"

	case strings.Contains(msg, "program too large"):
		return "program exceeds BPF complexity limit — file an issue with kernel version"

	case strings.Contains(msg, "unknown") && strings.Contains(msg, "attach type"):
		return "attach type not supported on this kernel — requires 5.15+"

	case strings.Contains(msg, "busy") || strings.Contains(msg, "in use"):
		return "resource already in use — another BPF program may be attached"

	case strings.Contains(msg, "libbpf"):
		return "libbpf error — ensure libbpf-dev is installed and up to date"

	default:
		return "check kernel version (5.8+ required), BTF support, and capabilities"
	}
}

// IsPermissionError returns true if the error is related to insufficient permissions.
func IsPermissionError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "eperm")
}

// IsBTFError returns true if the error is related to missing BTF support.
func IsBTFError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "btf") || strings.Contains(msg, "vmlinux")
}

// IsVerifierError returns true if the error is from the BPF verifier.
func IsVerifierError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "verifier") || strings.Contains(msg, "invalid")
}
