// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"strings"
	"testing"
)

func TestWrapLoadError(t *testing.T) {
	tests := []struct {
		name        string
		program     string
		err         error
		wantHint    string
		wantContain string
	}{
		{
			name:        "permission denied",
			program:     "syscall_latency",
			err:         errors.New("operation not permitted"),
			wantHint:    "run with sudo or grant CAP_BPF+CAP_PERFMON+CAP_SYS_ADMIN capabilities",
			wantContain: "syscall_latency",
		},
		{
			name:        "BTF missing",
			program:     "tcp_monitor",
			err:         errors.New("btf not found"),
			wantHint:    "kernel needs CONFIG_DEBUG_INFO_BTF=y (requires kernel 5.8+)",
			wantContain: "tcp_monitor",
		},
		{
			name:        "verifier error",
			program:     "disk_io",
			err:         errors.New("verifier rejected program"),
			wantHint:    "BPF verifier rejected the program — may need newer kernel or different approach",
			wantContain: "disk_io",
		},
		{
			name:        "memlock limit",
			program:     "oom_track",
			err:         errors.New("memlock rlimit exceeded"),
			wantHint:    "increase memlock limit: ulimit -l unlimited (or run as root)",
			wantContain: "oom_track",
		},
		{
			name:        "nil error",
			program:     "test",
			err:         nil,
			wantHint:    "",
			wantContain: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := WrapLoadError(tt.program, tt.err)

			if tt.err == nil {
				if wrapped != nil {
					t.Errorf("WrapLoadError(nil) = %v, want nil", wrapped)
				}
				return
			}

			if wrapped == nil {
				t.Fatal("WrapLoadError returned nil for non-nil error")
			}

			var loadErr *LoadError
			if !errors.As(wrapped, &loadErr) {
				t.Fatal("Wrapped error is not a *LoadError")
			}

			if loadErr.Program != tt.program {
				t.Errorf("Program = %q, want %q", loadErr.Program, tt.program)
			}

			if loadErr.Hint != tt.wantHint {
				t.Errorf("Hint = %q, want %q", loadErr.Hint, tt.wantHint)
			}

			errStr := wrapped.Error()
			if !strings.Contains(errStr, tt.wantContain) {
				t.Errorf("Error() = %q, want it to contain %q", errStr, tt.wantContain)
			}

			// Test Unwrap
			if !errors.Is(wrapped, tt.err) {
				t.Error("Unwrap() should return the original error")
			}
		})
	}
}

func TestIsPermissionError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "operation not permitted",
			err:  errors.New("operation not permitted"),
			want: true,
		},
		{
			name: "permission denied",
			err:  errors.New("permission denied"),
			want: true,
		},
		{
			name: "EPERM",
			err:  errors.New("error: EPERM"),
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("btf not found"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPermissionError(tt.err); got != tt.want {
				t.Errorf("IsPermissionError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsBTFError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "btf not found",
			err:  errors.New("btf not found"),
			want: true,
		},
		{
			name: "vmlinux missing",
			err:  errors.New("vmlinux not available"),
			want: true,
		},
		{
			name: "permission error",
			err:  errors.New("operation not permitted"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsBTFError(tt.err); got != tt.want {
				t.Errorf("IsBTFError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsVerifierError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "verifier rejected",
			err:  errors.New("verifier rejected program"),
			want: true,
		},
		{
			name: "invalid instruction",
			err:  errors.New("invalid BPF instruction"),
			want: true,
		},
		{
			name: "btf error",
			err:  errors.New("btf not found"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsVerifierError(tt.err); got != tt.want {
				t.Errorf("IsVerifierError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClassifyLoadError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantHint string
	}{
		{
			name:     "permission denied",
			err:      errors.New("operation not permitted"),
			wantHint: "run with sudo or grant CAP_BPF+CAP_PERFMON+CAP_SYS_ADMIN capabilities",
		},
		{
			name:     "memlock limit",
			err:      errors.New("memlock rlimit exceeded"),
			wantHint: "increase memlock limit: ulimit -l unlimited (or run as root)",
		},
		{
			name:     "BTF missing",
			err:      errors.New("btf not found"),
			wantHint: "kernel needs CONFIG_DEBUG_INFO_BTF=y (requires kernel 5.8+)",
		},
		{
			name:     "vmlinux missing",
			err:      errors.New("/sys/kernel/btf/vmlinux: no such file"),
			wantHint: "missing /sys/kernel/btf/vmlinux — kernel must be compiled with BTF support",
		},
		{
			name:     "verifier rejection",
			err:      errors.New("BPF verifier rejected: invalid"),
			wantHint: "BPF verifier rejected the program — may need newer kernel or different approach",
		},
		{
			name:     "tracepoint unavailable",
			err:      errors.New("no such file or directory: tracepoint"),
			wantHint: "tracepoint not available on this kernel — try kernel 5.10+ or file an issue",
		},
		{
			name:     "program too large",
			err:      errors.New("program too large: exceeds complexity limit"),
			wantHint: "program exceeds BPF complexity limit — file an issue with kernel version",
		},
		{
			name:     "unknown error",
			err:      errors.New("some unknown error"),
			wantHint: "check kernel version (5.8+ required), BTF support, and capabilities",
		},
		{
			name:     "nil error",
			err:      nil,
			wantHint: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint := classifyLoadError(tt.err)
			if hint != tt.wantHint {
				t.Errorf("classifyLoadError() = %q, want %q", hint, tt.wantHint)
			}
		})
	}
}
