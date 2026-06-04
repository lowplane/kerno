// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package preflight validates host prerequisites for running kerno.
// Each check is a small function returning a Result; the RunAll function
// aggregates them into a single report.
package preflight

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Status is the outcome of a single preflight check.
type Status int

const (
	// StatusPass indicates the check passed.
	StatusPass Status = iota
	// StatusWarn indicates a non-fatal issue (kerno can degrade gracefully).
	StatusWarn
	// StatusFail indicates a blocking issue (kerno cannot start).
	StatusFail
)

// String returns the human-readable label for a Status.
func (s Status) String() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusWarn:
		return "WARN"
	case StatusFail:
		return "FAIL"
	default:
		return "UNKNOWN"
	}
}

// MarshalText implements encoding.TextMarshaler for JSON output.
func (s Status) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// Result captures one preflight check outcome.
type Result struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"` // remediation hint
}

// CheckOptions carries configuration for filesystem-path overrides,
// enabling testability via fixtures (inject t.TempDir() paths instead of /proc).
type CheckOptions struct {
	ProcPath    string // default: "/proc"
	SysPath     string // default: "/sys"
	CgroupPath  string // default: "/sys/fs/cgroup"
	BTFPath     string // default: "/sys/kernel/btf/vmlinux"
	DebugFSPath string // default: "/sys/kernel/debug"
	TraceFSPath string // default: "/sys/kernel/tracing"
	OutputDir   string // default: "/var/log/kerno"
	PromAddr    string // default: ":9090"
}

// withDefaults fills zero-value fields with production paths.
func (o CheckOptions) withDefaults() CheckOptions {
	if o.ProcPath == "" {
		o.ProcPath = "/proc"
	}
	if o.SysPath == "" {
		o.SysPath = "/sys"
	}
	if o.CgroupPath == "" {
		o.CgroupPath = "/sys/fs/cgroup"
	}
	if o.BTFPath == "" {
		o.BTFPath = "/sys/kernel/btf/vmlinux"
	}
	if o.DebugFSPath == "" {
		o.DebugFSPath = "/sys/kernel/debug"
	}
	if o.TraceFSPath == "" {
		o.TraceFSPath = "/sys/kernel/tracing"
	}
	if o.OutputDir == "" {
		o.OutputDir = "/var/log/kerno"
	}
	if o.PromAddr == "" {
		o.PromAddr = ":9090"
	}
	return o
}

// Stable kernel capability ABI constants.
const (
	capNetAdmin = 12
	capPerfmon  = 38
	capBPF      = 39
)

// CheckKernelVersion verifies the running kernel is >= 5.8 (required for
// CAP_BPF and modern BTF support).
func CheckKernelVersion() Result {
	var utsname syscall.Utsname
	if err := syscall.Uname(&utsname); err != nil {
		return Result{
			Name:    "Linux kernel version",
			Status:  StatusFail,
			Message: fmt.Sprintf("failed to read kernel version: %v", err),
			Detail:  "unable to call uname(2) — this should not happen on Linux",
		}
	}

	release := utsNameToString(utsname.Release)
	major, minor, err := parseKernelVersion(release)
	if err != nil {
		return Result{
			Name:    "Linux kernel version",
			Status:  StatusFail,
			Message: fmt.Sprintf("failed to parse kernel version %q: %v", release, err),
		}
	}

	if major < 5 || (major == 5 && minor < 8) {
		return Result{
			Name:    "Linux kernel version",
			Status:  StatusFail,
			Message: fmt.Sprintf("kernel %d.%d is too old (need >= 5.8, running %s)", major, minor, release),
			Detail:  "upgrade to kernel 5.8+ for CAP_BPF and BTF support",
		}
	}

	return Result{
		Name:    "Linux kernel version",
		Status:  StatusPass,
		Message: fmt.Sprintf("Linux kernel >= 5.8 (running %s)", release),
	}
}

// CheckBTF verifies that /sys/kernel/btf/vmlinux is readable. It opens the
// file (not just stat) so a root-readable-only or zero-perm vmlinux fails
// here instead of later at eBPF load time.
func CheckBTF(opts CheckOptions) Result {
	f, err := os.Open(opts.BTFPath) //nolint:gosec // path is a controlled default or test fixture
	if err != nil {
		return Result{
			Name:    "BTF (BPF Type Format)",
			Status:  StatusFail,
			Message: fmt.Sprintf("%s not readable: %v", opts.BTFPath, err),
			Detail:  "kernel needs CONFIG_DEBUG_INFO_BTF=y (kernel >= 5.8 with BTF)",
		}
	}
	f.Close()
	return Result{
		Name:    "BTF (BPF Type Format)",
		Status:  StatusPass,
		Message: fmt.Sprintf("%s readable", opts.BTFPath),
	}
}

// CheckCgroupV2 verifies that cgroup v2 is mounted at the expected path.
func CheckCgroupV2(opts CheckOptions) Result {
	var stat unix.Statfs_t
	if err := unix.Statfs(opts.CgroupPath, &stat); err != nil {
		return Result{
			Name:    "cgroup v2",
			Status:  StatusFail,
			Message: fmt.Sprintf("failed to stat %s: %v", opts.CgroupPath, err),
			Detail:  "mount cgroup v2: sudo mount -t cgroup2 none /sys/fs/cgroup",
		}
	}

	const cgroup2Magic = 0x63677270
	if stat.Type != cgroup2Magic {
		return Result{
			Name:    "cgroup v2",
			Status:  StatusFail,
			Message: fmt.Sprintf("%s is not cgroup v2 (type=0x%x)", opts.CgroupPath, stat.Type),
			Detail:  "kerno requires cgroup v2; add systemd.unified_cgroup_hierarchy=1 to kernel cmdline",
		}
	}

	return Result{
		Name:    "cgroup v2",
		Status:  StatusPass,
		Message: fmt.Sprintf("cgroup v2 mounted at %s", opts.CgroupPath),
	}
}

// CheckCapBPF verifies that CAP_BPF is in the effective capability set.
func CheckCapBPF(caps uint64, capErr error) Result {
	if capErr != nil {
		return Result{
			Name:    "CAP_BPF",
			Status:  StatusFail,
			Message: fmt.Sprintf("failed to read capabilities: %v", capErr),
			Detail:  "run with sudo or grant CAP_BPF to the binary",
		}
	}
	if !hasCap(caps, capBPF) {
		return Result{
			Name:    "CAP_BPF",
			Status:  StatusFail,
			Message: "CAP_BPF not available",
			Detail:  "run with sudo or: sudo setcap cap_bpf+ep /usr/local/bin/kerno",
		}
	}
	return Result{
		Name:    "CAP_BPF",
		Status:  StatusPass,
		Message: "CAP_BPF available",
	}
}

// CheckCapPerfmon verifies that CAP_PERFMON is in the effective capability set.
func CheckCapPerfmon(caps uint64, capErr error) Result {
	if capErr != nil {
		return Result{
			Name:    "CAP_PERFMON",
			Status:  StatusFail,
			Message: fmt.Sprintf("failed to read capabilities: %v", capErr),
			Detail:  "run with sudo or grant CAP_PERFMON to the binary",
		}
	}
	if !hasCap(caps, capPerfmon) {
		return Result{
			Name:    "CAP_PERFMON",
			Status:  StatusFail,
			Message: "CAP_PERFMON not available",
			Detail:  "run with sudo or: sudo setcap cap_perfmon+ep /usr/local/bin/kerno",
		}
	}
	return Result{
		Name:    "CAP_PERFMON",
		Status:  StatusPass,
		Message: "CAP_PERFMON available",
	}
}

// CheckProcReadable verifies that /proc/version is readable.
func CheckProcReadable(opts CheckOptions) Result {
	path := filepath.Join(opts.ProcPath, "version")
	f, err := os.Open(path) //nolint:gosec // path is constructed from a controlled prefix + constant
	if err != nil {
		return Result{
			Name:    "/proc readable",
			Status:  StatusFail,
			Message: fmt.Sprintf("%s not readable: %v", path, err),
			Detail:  "mount proc: sudo mount -t proc proc /proc",
		}
	}
	f.Close()
	return Result{
		Name:    "/proc readable",
		Status:  StatusPass,
		Message: "/proc readable",
	}
}

// CheckCapNetAdmin verifies that CAP_NET_ADMIN is in the effective capability
// set. This is a WARN (not FAIL) because kerno can degrade gracefully — only
// the TCP retransmit collector requires it.
func CheckCapNetAdmin(caps uint64, capErr error) Result {
	if capErr != nil {
		return Result{
			Name:    "CAP_NET_ADMIN",
			Status:  StatusWarn,
			Message: fmt.Sprintf("failed to read capabilities: %v", capErr),
			Detail:  "TCP retransmit collector will degrade; run with sudo for full coverage",
		}
	}
	if !hasCap(caps, capNetAdmin) {
		return Result{
			Name:    "CAP_NET_ADMIN",
			Status:  StatusWarn,
			Message: "CAP_NET_ADMIN missing — TCP retransmit collector will degrade",
			Detail:  "run with sudo or: sudo setcap cap_net_admin+ep /usr/local/bin/kerno",
		}
	}
	return Result{
		Name:    "CAP_NET_ADMIN",
		Status:  StatusPass,
		Message: "CAP_NET_ADMIN available",
	}
}

// CheckOutputDir verifies that the output directory exists and is writable.
func CheckOutputDir(opts CheckOptions) Result {
	info, err := os.Stat(opts.OutputDir)
	if err != nil {
		return Result{
			Name:    "Output directory",
			Status:  StatusFail,
			Message: fmt.Sprintf("output directory %s does not exist", opts.OutputDir),
			Detail:  fmt.Sprintf("create it: sudo mkdir -p %s && sudo chmod 755 %s", opts.OutputDir, opts.OutputDir),
		}
	}
	if !info.IsDir() {
		return Result{
			Name:    "Output directory",
			Status:  StatusFail,
			Message: fmt.Sprintf("%s exists but is not a directory", opts.OutputDir),
		}
	}

	// Write test file to verify write access.
	probe := filepath.Join(opts.OutputDir, ".kerno-preflight-probe")
	f, err := os.Create(probe) //nolint:gosec // path is constructed from a controlled prefix + constant
	if err != nil {
		return Result{
			Name:    "Output directory",
			Status:  StatusFail,
			Message: fmt.Sprintf("output directory %s not writable: %v", opts.OutputDir, err),
			Detail:  fmt.Sprintf("fix permissions: sudo chown $USER %s", opts.OutputDir),
		}
	}
	f.Close()
	_ = os.Remove(probe) // best-effort cleanup

	return Result{
		Name:    "Output directory",
		Status:  StatusPass,
		Message: fmt.Sprintf("output directory %s writable", opts.OutputDir),
	}
}

// CheckPortFree verifies that the Prometheus metrics port is available.
// This is a point-in-time check (TOCTOU) — the port may be claimed between
// the check and kerno startup.
func CheckPortFree(opts CheckOptions) Result {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", opts.PromAddr)
	if err != nil {
		return Result{
			Name:    "Prometheus port",
			Status:  StatusFail,
			Message: fmt.Sprintf("port %s already in use", opts.PromAddr),
			Detail:  "another process is listening on this port; change prometheus.addr in config or stop the conflicting process",
		}
	}
	ln.Close()

	// Extract port number for display.
	_, port, _ := net.SplitHostPort(opts.PromAddr)
	return Result{
		Name:    "Prometheus port",
		Status:  StatusPass,
		Message: fmt.Sprintf("port %s available (snapshot; may be claimed before startup)", port),
	}
}

// CheckTracefs verifies that tracefs or debugfs/tracing is mounted.
// Modern kernels (5.1+) mount tracefs at /sys/kernel/tracing independently
// of debugfs. Older setups expose it via /sys/kernel/debug/tracing.
// Both are valid — we check both paths and WARN only if neither exists.
func CheckTracefs(opts CheckOptions) Result {
	if _, err := os.Stat(opts.TraceFSPath); err == nil {
		return Result{
			Name:    "tracefs",
			Status:  StatusPass,
			Message: fmt.Sprintf("tracefs mounted at %s", opts.TraceFSPath),
		}
	}
	debugTracing := filepath.Join(opts.DebugFSPath, "tracing")
	if _, err := os.Stat(debugTracing); err == nil {
		return Result{
			Name:    "tracefs",
			Status:  StatusPass,
			Message: fmt.Sprintf("tracefs available via debugfs at %s", debugTracing),
		}
	}
	return Result{
		Name:    "tracefs",
		Status:  StatusWarn,
		Message: "tracefs not found at /sys/kernel/tracing or /sys/kernel/debug/tracing",
		Detail:  "mount tracefs: sudo mount -t tracefs tracefs /sys/kernel/tracing",
	}
}

// RunAll executes all preflight checks and returns aggregated results.
func RunAll(opts CheckOptions) []Result {
	opts = opts.withDefaults()

	// Read capabilities once, share across capability checks.
	caps, capErr := getEffectiveCaps()

	return []Result{
		CheckKernelVersion(),
		CheckBTF(opts),
		CheckCgroupV2(opts),
		CheckCapBPF(caps, capErr),
		CheckCapPerfmon(caps, capErr),
		CheckProcReadable(opts),
		CheckCapNetAdmin(caps, capErr),
		CheckOutputDir(opts),
		CheckPortFree(opts),
		CheckTracefs(opts),
	}
}

// getEffectiveCaps returns the combined effective capability bitmask
// for the current process using the stable Linux capability ABI.
func getEffectiveCaps() (uint64, error) {
	hdr := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0, // current process
	}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0, fmt.Errorf("capget: %w", err)
	}
	return uint64(data[0].Effective) | (uint64(data[1].Effective) << 32), nil
}

// hasCap checks whether a specific capability bit is set.
func hasCap(caps uint64, bit int) bool {
	return caps&(1<<bit) != 0
}

// parseKernelVersion extracts major.minor from a uname release string.
// Handles distribution suffixes robustly:
//
//	"6.17.0"                       → (6, 17)
//	"5.15.0-91-generic"            → (5, 15)   (Ubuntu)
//	"5.14.0-70.13.1.el9_0.x86_64" → (5, 14)   (RHEL)
//	"6.1.0-rc4"                    → (6, 1)    (release candidate)
//	"5.8.0+debug"                  → (5, 8)    (custom builds)
func parseKernelVersion(release string) (major, minor int, err error) {
	// Strip everything after first hyphen, plus, or space to isolate
	// the upstream semver core before distro metadata.
	clean := release
	for _, sep := range []string{"-", "+", " "} {
		if idx := strings.Index(clean, sep); idx > 0 {
			clean = clean[:idx]
		}
	}
	parts := strings.Split(clean, ".")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("invalid kernel release format: %q", release)
	}
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("parsing major version from %q: %w", release, err)
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("parsing minor version from %q: %w", release, err)
	}
	return major, minor, nil
}

// utsNameToString converts a [65]int8 (or [65]byte on some archs) utsname
// field to a Go string, trimming at the first null byte.
func utsNameToString(arr [65]int8) string {
	buf := make([]byte, 0, len(arr))
	for _, b := range arr {
		if b == 0 {
			break
		}
		buf = append(buf, byte(b))
	}
	return string(buf)
}
