# KERNO - Production Roadmap & Task Plan

> **Single source of truth** for what to build, in what order, and why.
> Every task is sequenced for **maximum impact per hour invested.**
> Updated: 2026-04-12 | Owner: Shivam Kumar (@btwshivam)

---

## Project Goal

**Kerno is the system-level incident diagnosis engine for Kubernetes and Linux.** When something breaks in production - a slow pod, a stuck node, a mysterious cascade, a silent throttle - Kerno watches the kernel directly with eBPF and explains the root cause in plain English. Every signal a K8s engineer has ever wished `top` / `iostat` / `kubectl describe` showed at the same time, Kerno surfaces in one report. Bare-VM and standalone Linux installs are fully supported as first-class targets alongside Kubernetes.

The product promise: **if it can break production, kerno detects it and explains why.**

**Detection target (v0.2):** 47 diagnostic rules covering: cgroup throttling (CPU/memory/IO/PID), DNS failures, TCP connection failures/drops/resets, memory leaks/pressure/swap, lock contention, socket/conntrack/port exhaustion, kernel warnings/hangs, process crash loops, filesystem/disk/inode exhaustion, thermal throttling - all enriched with Kubernetes pod/namespace/container context.

---

## Guiding Principles

1. **Ship `kerno doctor` first.** It is the README GIF, the tweet, the Hacker News post. Everything else exists to support it.
2. **One working binary > ten perfect abstractions.** Get `sudo kerno doctor` producing real output on a stressed VM before over-engineering internals.
3. **Production-grade from day one.** Structured logging, graceful shutdown, proper error handling, meaningful tests - not bolted on later.
4. **Linux core, Kubernetes-native deployment.** Every feature must still work on a bare VM, but K8s is the primary deployment target. New features should be designed with pod / namespace / service context in mind from day one - not bolted on later. **Bare-VM support is an invariant, not a feature: every collector must degrade gracefully outside a cgroup-v2 / K8s context, but no design decision is made for bare-VM users first.**
5. **Measure overhead obsessively.** If Kerno adds >1% CPU, it's a bug.
6. **Open-source hygiene matters.** LICENSE, CONTRIBUTING, DCO, CI, releases - these are features, not chores.
7. **Positioning: Cilium shows traffic. Kerno explains incidents.** We are an incident explanation engine, not a network observability tool. Topology features exist as *context* for diagnosis, never as the main pitch. If a roadmap item sounds like a feature Cilium / Hubble / Linkerd already ships, demote it to supporting plumbing or cut it.
8. **The viral asset is the demo GIF, not the architecture.** A 30-second VHS recording of `kerno doctor` finding a real problem on a stressed VM is more important than any single feature. Treat it as a P0 deliverable, not an afterthought.

---

## Phase 0 - Skeleton & Build System *(Week 1)* ✅ COMPLETE

> **Goal:** `make build` produces a `kerno` binary. `make test` passes. CI is green.

### 0.1 Repository Bootstrap

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 0.1.1 | Initialize Go module `github.com/lowplane/kerno` | P0 | Go 1.22+ with toolchain directive |
| 0.1.2 | Create canonical directory layout (see [Structure](#directory-structure)) | P0 | Follow `golang-standards/project-layout` |
| 0.1.3 | Add `.gitignore` (Go + C object files + `*.o` + `bin/`) | P0 | |
| 0.1.4 | Add `.editorconfig` (tabs for Go, spaces for C, LF everywhere) | P1 | Consistency across contributors |
| 0.1.5 | Add `LICENSE` (Apache 2.0 - already exists) | P0 | ✅ Done |
| 0.1.6 | Add `CONTRIBUTING.md` with DCO sign-off requirement | P0 | Mandatory for CNCF |
| 0.1.7 | Add `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1) | P0 | Mandatory for CNCF |
| 0.1.8 | Add `SECURITY.md` (vulnerability disclosure process) | P0 | |
| 0.1.9 | Add `GOVERNANCE.md` (maintainer ladder) | P1 | Can be minimal initially |

### 0.2 Build System

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 0.2.1 | Create `Makefile` with targets: `bpf`, `generate`, `build`, `test`, `lint`, `clean`, `docker` | P0 | Single entry point for all builds |
| 0.2.2 | eBPF compilation: `clang -O2 -g -target bpf` → `.o` files | P0 | Requires clang 14+, libbpf-dev |
| 0.2.3 | `bpf2go` code generation: `//go:generate` in each loader | P0 | `cilium/ebpf/cmd/bpf2go` |
| 0.2.4 | `vmlinux.h` generation from `/sys/kernel/btf/vmlinux` | P0 | Checked into repo for CI reproducibility |
| 0.2.5 | Binary versioning via `-ldflags` (`version`, `commit`, `date`) | P0 | `kerno --version` works from day one |
| 0.2.6 | `goreleaser` config for multi-arch release (amd64, arm64) | P1 | `.goreleaser.yml` |
| 0.2.7 | `Dockerfile` (multi-stage: build + distroless/static) | P1 | Minimal attack surface |

### 0.3 CI/CD Pipeline (GitHub Actions)

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 0.3.1 | **Lint** job: `golangci-lint` with strict config | P0 | `.golangci.yml` |
| 0.3.2 | **Unit test** job: `go test -race -coverprofile` | P0 | No root needed |
| 0.3.3 | **BPF compile** job: build eBPF objects (needs clang + headers) | P0 | Use Ubuntu 22.04 runner |
| 0.3.4 | **Integration test** job: load eBPF in VM (optional, expensive) | P2 | Use `kernel.org` runner or QEMU later |
| 0.3.5 | **Release** job: goreleaser on tag push | P1 | `v*` tags trigger release |
| 0.3.6 | **Docker** job: build + push `ghcr.io/lowplane/kerno` | P1 | On tag + main branch |
| 0.3.7 | Badge in README: CI, Go Report Card, License | P1 | |

### Directory Structure

```
kerno/
├── cmd/
│   └── kerno/
│       └── main.go                    # Entry point
│
├── internal/
│   ├── cli/                           # Cobra command definitions
│   │   ├── root.go
│   │   ├── doctor.go
│   │   ├── trace.go
│   │   ├── watch.go
│   │   ├── audit.go
│   │   ├── slo.go
│   │   └── start.go
│   │
│   ├── bpf/                           # eBPF C source + generated Go bindings
│   │   ├── headers/
│   │   │   └── vmlinux.h
│   │   ├── syscall_latency.c          # eBPF program
│   │   ├── syscall_latency.go         # Go loader (bpf2go generates _bpfel.go / _bpfeb.go)
│   │   ├── tcp_monitor.c
│   │   ├── tcp_monitor.go
│   │   ├── oom_track.c
│   │   ├── oom_track.go
│   │   ├── file_audit.c
│   │   ├── file_audit.go
│   │   ├── disk_io.c
│   │   ├── disk_io.go
│   │   ├── sched_delay.c
│   │   ├── sched_delay.go
│   │   └── fd_track.c / fd_track.go
│   │
│   ├── collector/                     # Signal collection + aggregation
│   │   ├── collector.go               # Collector interface
│   │   ├── registry.go                # Collector registry
│   │   ├── syscall/
│   │   │   ├── collector.go
│   │   │   ├── aggregator.go          # Percentile computation
│   │   │   └── collector_test.go
│   │   ├── tcp/
│   │   ├── oom/
│   │   ├── file/
│   │   ├── disk/
│   │   ├── sched/
│   │   └── fd/
│   │
│   ├── doctor/                        # kerno doctor engine
│   │   ├── engine.go                  # Orchestrator
│   │   ├── signals.go                 # Aggregated signal snapshot
│   │   ├── finding.go                 # Finding type + severity
│   │   ├── rules/                     # One file per diagnostic rule
│   │   │   ├── rule.go                # Rule interface
│   │   │   ├── disk_io.go
│   │   │   ├── oom.go
│   │   │   ├── tcp_retransmit.go
│   │   │   ├── scheduler.go
│   │   │   ├── fd_leak.go
│   │   │   └── syscall_latency.go
│   │   ├── renderer/                  # Output renderers
│   │   │   ├── renderer.go            # Renderer interface
│   │   │   ├── pretty.go              # Terminal colored output
│   │   │   ├── json.go
│   │   │   └── prometheus.go
│   │   └── engine_test.go
│   │
│   ├── adapter/                       # Environment context enrichment
│   │   ├── adapter.go                 # Adapter interface
│   │   ├── detect.go                  # Auto-detect environment
│   │   ├── kubernetes.go              # K8s pod/namespace enrichment
│   │   ├── systemd.go                 # systemd unit enrichment
│   │   └── baremetal.go               # Hostname/cgroup enrichment
│   │
│   ├── export/                        # Metrics & telemetry export
│   │   ├── prometheus.go              # /metrics handler
│   │   └── otlp.go                    # OTLP gRPC exporter (v0.2+)
│   │
│   ├── slo/                           # SLO bridge engine (v0.3+)
│   │   ├── engine.go
│   │   ├── budget.go
│   │   └── crd.go
│   │
│   ├── config/                        # Viper-based config
│   │   ├── config.go                  # Config struct + defaults
│   │   ├── validate.go                # Config validation
│   │   └── config_test.go
│   │
│   └── version/                       # Build metadata
│       └── version.go
│
├── bpf/                               # Symlink or mirror of internal/bpf/*.c
│                                       # (for people who just want to read the C)
│
├── deploy/
│   ├── kubernetes/
│   │   ├── daemonset.yaml
│   │   ├── rbac.yaml
│   │   ├── namespace.yaml
│   │   └── service.yaml
│   └── helm/
│       └── kerno/
│           ├── Chart.yaml
│           ├── values.yaml
│           └── templates/
│
├── docs/
│   ├── architecture.md
│   ├── ebpf-programs.md
│   └── getting-started.md
│
├── scripts/
│   ├── install.sh                     # curl | sh installer
│   └── stress-test.sh                 # Generate load for demo
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   └── release.yml
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── PULL_REQUEST_TEMPLATE.md
│
├── Makefile
├── go.mod
├── go.sum
├── .goreleaser.yml
├── .golangci.yml
├── .editorconfig
├── .gitignore
├── LICENSE
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── GOVERNANCE.md
└── README.md
```

### Definition of Done - Phase 0

- [x] `git clone && make build` works on Ubuntu 22.04 with clang+libbpf installed
- [x] `./bin/kerno --version` prints version, commit hash, build date
- [x] `make test` runs (even if tests are trivial stubs)
- [x] `make lint` passes with zero warnings
- [x] GitHub Actions CI passes on push to `main`
- [x] README has project description, badge row, and "coming soon" for features

---

## Phase 1 - Core eBPF Programs *(Week 2–3)* ✅ COMPLETE

> **Goal:** Six eBPF programs compile, load into a kernel, and emit events to ring buffers that Go can read.
> **Status:** All 6 C programs written, Go loaders with bpf2go directives, stub generator for non-eBPF builds. Programs need fleshing out with full CO-RE event capture.

### 1.1 Common eBPF Infrastructure

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 1.1.1 | Generate `vmlinux.h` from BTF and add to `internal/bpf/headers/` | P0 | `bpftool btf dump file /sys/kernel/btf/vmlinux format c` |
| 1.1.2 | Create shared header `internal/bpf/headers/kerno.h` with common structs, constants, ring buffer macros | P0 | Consistent event format across all programs |
| 1.1.3 | Define event structs in `kerno.h` that match Go struct layout exactly | P0 | Use `__attribute__((packed))` or explicit padding |
| 1.1.4 | Add `bpf2go` generate directives in each Go loader file | P0 | `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ...` |

### 1.2 eBPF Programs (in build order)

Each program must: compile without warnings, pass the verifier on kernel ≥5.8, use CO-RE for portability, emit events via `BPF_MAP_TYPE_RINGBUF`.

| # | Program | Hook Points | Event Data | Priority |
|---|---------|-------------|------------|----------|
| 1.2.1 | **`syscall_latency.c`** | `tracepoint/raw_syscalls/sys_enter` + `sys_exit` | pid, comm, syscall_nr, latency_ns, cgroup_id | P0 |
| 1.2.2 | **`tcp_monitor.c`** | `tracepoint/tcp/tcp_retransmit_skb`, `tracepoint/sock/inet_sock_set_state`, `fentry/tcp_rcv_established` (RTT) | pid, comm, saddr, daddr, sport, dport, state, retransmits, rtt_us | P0 |
| 1.2.3 | **`oom_track.c`** | `kprobe/oom_kill_process` + `tracepoint/oom/mark_victim` | victim_pid, victim_comm, total_pages, rss_pages, oom_score, cgroup_path | P0 |
| 1.2.4 | **`disk_io.c`** | `tracepoint/block/block_rq_issue` + `block_rq_complete` | dev, sector, latency_ns, op (R/W/S), bytes | P0 |
| 1.2.5 | **`sched_delay.c`** | `tracepoint/sched/sched_wakeup` + `sched_switch` | pid, comm, runq_delay_ns, cpu | P0 |
| 1.2.6 | **`fd_track.c`** | `tracepoint/syscalls/sys_exit_openat` + `sys_exit_close` + `sys_exit_socket` | pid, comm, fd_count_delta (+1/−1) | P1 |
| 1.2.7 | **`file_audit.c`** | `kprobe/vfs_open` or `fentry/do_filp_open` | pid, comm, uid, filename, flags | P1 |

### 1.3 Go BPF Loaders

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 1.3.1 | Base `Loader` interface: `Load(opts) → (closer, error)` | P0 | Every BPF program gets a typed Go loader |
| 1.3.2 | Implement `SyscallLatencyLoader` - loads program, returns ringbuf reader | P0 | First end-to-end proof: C → kernel → Go |
| 1.3.3 | Implement remaining 5 loaders | P0 | Follow same pattern |
| 1.3.4 | Graceful cleanup: close links + maps + ringbuf on `SIGINT`/`SIGTERM` | P0 | Resource leaks = production disaster |
| 1.3.5 | Error wrapping: every BPF error includes verifier log excerpt | P0 | "Failed to load" with no context helps nobody |

### Design Decision: `tracepoint` vs `kprobe` vs `fentry`

| Approach | Stability | Performance | Kernel Requirement |
|----------|-----------|-------------|--------------------|
| `tracepoint` | ✅ Best - kernel ABI | Good | 4.7+ |
| `kprobe` | ⚠️ Internal API, can break | Good | 4.1+ |
| `fentry` | ⚠️ Internal API, can break | ✅ Best - no pt_regs | 5.5+ |

**Decision:** Use `tracepoint` wherever possible (syscalls, tcp, sched, block). Fall back to `kprobe`/`fentry` only for hooks with no tracepoint (OOM, file_audit).

### Definition of Done - Phase 1

- [x] `make bpf` compiles all 6+ eBPF `.c` files to `.o` without warnings
- [x] `make generate` runs `bpf2go` and produces `*_bpfel.go` / `*_bpfeb.go`
- [x] A standalone `main.go` test harness can load each program into the kernel and print raw events
- [ ] Each program verified on kernel 5.15 and 6.1 (two LTS versions)
- [x] Zero verifier warnings at `log_level=1`

---

## Phase 2 - Collector Framework & Aggregation *(Week 3–4)* ✅ COMPLETE

> **Goal:** Raw ring buffer events are consumed, enriched, and aggregated into typed signal snapshots (percentiles, rates, counts).
> **Status:** Full implementation. 6 live collectors (syscall, tcp, oom, disk, sched, fd) consume ringbuf events and produce typed snapshots. Bounded log2-bucket histogram (`internal/collector/aggregator`) provides O(1) insertion and ~24ns Record / 29ns Percentile estimation. Per-key LRU caps memory growth on high-cardinality workloads. Wired into `kerno doctor` with graceful eBPF load-failure degradation. Sliding multi-window aggregation deferred to Phase 14.4 (--watch mode).

### 2.1 Collector Interface

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 2.1.1 | Define `Collector` interface: `Start(ctx) error`, `Stop()`, `Signals() <-chan Signal` | P0 | |
| 2.1.2 | Define `Signal` sum type (one variant per signal category) | P0 | |
| 2.1.3 | Create `Registry` - manages collector lifecycle, fan-in of signals | P0 | |
| 2.1.4 | Implement graceful context cancellation propagation | P0 | |

### 2.2 Per-Signal Collectors

Each collector: reads ring buffer in a goroutine, parses binary events, enriches with adapter metadata, and either streams raw events or aggregates into snapshots.

| # | Collector | Aggregation | Output | Priority |
|---|-----------|-------------|--------|----------|
| 2.2.1 | **SyscallCollector** | HDR histogram per (syscall_nr, comm) → p50/p95/p99/count over window | `SyscallSnapshot` | P0 |
| 2.2.2 | **TCPCollector** | Per-connection tracking (4-tuple) → retransmit rate, RTT trend | `TCPSnapshot` | P0 |
| 2.2.3 | **OOMCollector** | Event log (no aggregation - every OOM is critical) | `OOMEvent` stream | P0 |
| 2.2.4 | **DiskIOCollector** | HDR histogram per (device, op) → p50/p95/p99, queue depth | `DiskIOSnapshot` | P0 |
| 2.2.5 | **SchedCollector** | HDR histogram per (comm) → runq delay p50/p95/p99 | `SchedSnapshot` | P0 |
| 2.2.6 | **FDCollector** | Per-PID running FD counter → delta/sec (ring buffer + map) | `FDSnapshot` | P1 |
| 2.2.7 | **FileAuditCollector** | Event log with path matches against watch list | `FileEvent` stream | P1 |

### 2.3 Aggregation Infrastructure

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 2.3.1 | Integrate `HdrHistogram-Go` or implement T-Digest for percentile computation | P0 | Must handle millions of events per window |
| 2.3.2 | Sliding window aggregation: 1s, 10s, 30s, 60s buckets | P0 | Doctor uses 30s; --watch mode uses 1s |
| 2.3.3 | Memory-bounded: cap per-key histogram count with LRU eviction | P0 | Avoid unbounded growth |
| 2.3.4 | Atomic snapshot: `collector.Snapshot()` returns copy, not reference | P0 | Reader and writer are separate goroutines |

### 2.4 Combined Signals Snapshot

```go
// The single struct that doctor rules and exporters all consume
type Signals struct {
    Timestamp  time.Time
    Duration   time.Duration   // analysis window
    Host       HostInfo
    Syscall    SyscallSnapshot
    TCP        TCPSnapshot
    OOM        []OOMEvent
    DiskIO     DiskIOSnapshot
    Sched      SchedSnapshot
    FD         FDSnapshot
    Files      []FileEvent
}
```

### Definition of Done - Phase 2

- [x] `kerno trace syscall` prints live per-syscall percentiles refreshing every 1s
- [x] `kerno watch tcp` prints live TCP connections with RTT and retransmit count
- [x] `Signals` snapshot struct is populated from a 30s collection window
- [x] Memory usage is <50MB under 100K events/s sustained load
- [x] Unit tests for aggregation math (histogram percentiles, rate computation)

---

## Phase 3 - `kerno doctor` *(Week 4–6)* ✅ COMPLETE

> **Goal:** `sudo kerno doctor` runs for 30s and prints a ranked, colored, human-readable diagnostic report. This is the **#1 deliverable** of the entire project.
> **Status:** Doctor Engine fully implemented - 9 diagnostic rules, Finding struct with ranking, PrettyRenderer + JSONRenderer, Engine orchestrator with optional AI Analyzer, 28 tests passing. Wired into CLI with --ai/--no-ai, --output, --exit-code, --continuous flags. Needs live collectors (Phase 2) for real data.

### 3.1 Doctor Engine

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 3.1.1 | `doctor.Engine` struct - owns collectors, rules, renderer | P0 | |
| 3.1.2 | `Engine.Run(ctx)` - collect → evaluate → rank → render pipeline | P0 | |
| 3.1.3 | Progress spinner during 30s collection window (`briandowns/spinner` or custom) | P0 | UX: user must see it's working |
| 3.1.4 | Configurable duration flag (`--duration 10s`) | P0 | |
| 3.1.5 | Graceful early exit on Ctrl+C (print partial results) | P0 | |

### 3.2 Diagnostic Rules

Each rule: receives `Signals` snapshot → returns `*Finding` or `nil`.

| # | Rule | Trigger Condition | Severity | ETA Calculation |
|---|------|-------------------|----------|-----------------|
| 3.2.1 | **DiskIOBottleneck** | fsync p99 > 50ms OR disk queue > 8 OR any op p99 > 200ms | CRITICAL | N/A |
| 3.2.2 | **OOMImminent** | memory > 90% AND positive growth rate | CRITICAL | `(limit - current) / growth_rate` |
| 3.2.3 | **OOMKillOccurred** | Any OOM event in window | CRITICAL | N/A |
| 3.2.4 | **TCPRetransmitStorm** | Retransmit rate > 2% | CRITICAL | N/A |
| 3.2.5 | **TCPRTTDegradation** | RTT p99 > 10ms AND trending up | WARNING | N/A |
| 3.2.6 | **SchedulerContention** | runq delay p99 > 5ms | WARNING if >5ms, CRITICAL if >20ms | N/A |
| 3.2.7 | **FDLeak** | FD growth > 10/sec sustained | WARNING | `(ulimit - current) / growth_rate` |
| 3.2.8 | **SyscallLatencyHigh** | Any syscall p99 > 100ms | WARNING / CRITICAL (>500ms) | N/A |
| 3.2.9 | **SyscallErrorRate** ✅ | syscall error rate > 1% | WARNING / CRITICAL (>10%) | N/A |
| 3.2.10 | **HealthySystem** ✅ | No findings above → emit "all clear" | INFO | N/A |

### 3.3 Finding Struct & Ranking

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 3.3.1 | `Finding` struct: Severity, Title, Signal, Cause, Impact, Evidence, Fix, ETA | P0 | As designed in idea.md |
| 3.3.2 | Ranking algorithm: sort by severity DESC → ETA ASC → impact score DESC | P0 | CRITICAL before WARNING before INFO |
| 3.3.3 | "Recommended Action Order" generation from ranked findings | P0 | Numbered list: `[NOW]`, `[5 MIN]`, `[MONITOR]` |

### 3.4 Renderers

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 3.4.1 | **Pretty renderer** (default): colored terminal output matching idea.md mockup exactly | P0 | `fatih/color` or `charmbracelet/lipgloss` |
| 3.4.2 | Box-drawing header: `╔══ KERNO DOCTOR ══╗` | P0 | Brand identity |
| 3.4.3 | Severity icons: 🔴 CRITICAL, 🟡 WARNING, 🔵 INFO, ✅ Healthy | P0 | |
| 3.4.4 | System summary footer (events collected, programs loaded, overhead) | P0 | |
| 3.4.5 | **JSON renderer** (`--output json`): structured output for scripting | P0 | Machine-readable |
| 3.4.6 | `--no-color` flag for piped output | P0 | Detect `NO_COLOR` env var too |
| 3.4.7 | `--only-critical` flag | P1 | |

### 3.5 Notifications (Phase 3.5)

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 3.5.1 | `--notify slack://webhook_url` - POST JSON to Slack incoming webhook | P1 | Only critical findings |
| 3.5.2 | `--notify pagerduty://routing_key` - trigger PD incident | P2 | v2 Events API |
| 3.5.3 | `--exit-code` - exit 0 if healthy, 1 if critical findings | P0 | CI/CD integration |

### 3.6 Continuous Mode

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 3.6.1 | `--continuous` flag: re-run analysis every `--interval` (default 60s) | P1 | |
| 3.6.2 | Diff between runs: "NEW finding" / "RESOLVED" | P2 | |

### Definition of Done - Phase 3

- [x] `sudo kerno doctor` on a fresh Ubuntu 22.04 VM produces a correct report (verified on Ubuntu 24.04 / kernel 6.17 via `scripts/verify.sh`)
- [x] Under synthetic stress (`stress-ng`), it detects at least: high syscall latency, CPU contention, disk I/O (`scripts/verify.sh stress_ng` PASS)
- [x] Under TCP retransmit injection (`tc netem`), it detects retransmit storm (`scripts/verify.sh tc_netem` PASS — 30% loss on lo + chaos tcp-loss)
- [x] Under memory pressure (`stress-ng --vm`), it warns about OOM risk with correct ETA (`scripts/verify.sh oom_pressure` PASS — `/proc/meminfo` poller + ETA derivation)
- [x] `--output json` produces valid, parseable JSON
- [x] `--exit-code` returns 1 when critical findings exist
- [ ] **Record the demo GIF** (`vhs` / `asciinema`) and place in README — `make demo` ready; awaiting `vhs` install
- [x] On a healthy idle system, report says "✅ All kernel signals within normal thresholds"

---

## Phase 4 - CLI & Daemon Mode *(Week 6–7)* ✅ COMPLETE

> **Goal:** Full CLI with `trace`, `watch`, `audit`, and `start` subcommands.
> **Status:** All Section-10 commands shipped. doctor (full pipeline), explain (AI), predict, start (daemon + Prometheus), trace (syscall/disk/sched), watch (tcp/oom/fd), audit (files via inotify), chaos (7 scenarios), version. Auto-detect log format (text in TTY / JSON in CI/k8s/journald). KERNO_CONFIG env var. Grouped help. Live spinner. --quiet mode. eBPF degradation panel in pretty render.

### 4.1 CLI Architecture

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 4.1.1 | Root command with global flags (`--config`, `--log-level`, `--output`, `--no-color`, `--namespace`) | P0 | `cobra` + `viper` |
| 4.1.2 | `kerno doctor` (already built in Phase 3) | P0 | ✅ |
| 4.1.3 | `kerno trace syscall [--filter] [--pid] [--top] [--percentile]` | P0 | |
| 4.1.4 | `kerno trace disk [--op] [--threshold] [--process]` | P0 | |
| 4.1.5 | `kerno trace sched [--threshold] [--namespace]` | P1 | |
| 4.1.6 | `kerno watch tcp [--retransmits] [--threshold-rtt]` | P0 | |
| 4.1.7 | `kerno watch oom [--threshold] [--alert]` | P0 | |
| 4.1.8 | `kerno watch fd [--threshold]` | P1 | |
| 4.1.9 | `kerno audit files [--watch] [--sensitive] [--pod]` | P1 | |
| 4.1.10 | `kerno start` - daemon mode: all collectors + Prometheus + Incident CRD writer | P0 | DaemonSet entry point |
| 4.1.11 | `kerno version` | P0 | |

### 4.2 Configuration System

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 4.2.1 | Config struct with Viper binding (`/etc/kerno/config.yaml`) | P0 | Defaults match idea.md spec |
| 4.2.2 | Config validation at startup (fail fast with clear errors) | P0 | `go-playground/validator` |
| 4.2.3 | Environment variable overrides: `KERNO_LOG_LEVEL`, `KERNO_PROMETHEUS_ADDR` | P0 | 12-factor |
| 4.2.4 | Flag → env var → config file → default precedence | P0 | Standard Viper behavior |

### 4.3 Structured Logging

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 4.3.1 | `log/slog` (stdlib) with JSON handler for daemon mode | P0 | |
| 4.3.2 | Text handler for interactive CLI mode | P0 | |
| 4.3.3 | Request-scoped fields: collector name, event count, duration | P0 | |
| 4.3.4 | Log levels: DEBUG (per-event data), INFO (lifecycle), WARN (degraded), ERROR (failures) | P0 | |

### Definition of Done - Phase 4

- [x] Every CLI command listed in idea.md Section 10 is implemented (audit files via inotify; SLO subcommands deferred to Phase 11)
- [x] `kerno start --prometheus=:9090` runs as a long-lived daemon
- [x] Config file + env vars work with correct precedence
- [x] All commands show `--help` with correct descriptions and examples
- [x] Structured JSON logs in daemon mode; colored human logs in CLI mode (auto-detect via stderr TTY)

---

## Phase 5 - Prometheus Metrics Export *(Week 7–8)*

> **Goal:** `kerno start` exposes `/metrics` that Prometheus can scrape.

### 5.1 Metrics

| # | Metric | Labels | Type | Priority |
|---|--------|--------|------|----------|
| 5.1.1 | `kerno_syscall_duration_nanoseconds` | `syscall`, `process`, `namespace`, `pod`, `quantile` | Summary | P0 |
| 5.1.2 | `kerno_syscall_total` | `syscall`, `process`, `namespace`, `pod` | Counter | P0 |
| 5.1.3 | `kerno_tcp_rtt_nanoseconds` | `src_pod`, `dst_service`, `namespace`, `quantile` | Summary | P0 |
| 5.1.4 | `kerno_tcp_retransmits_total` | `src_pod`, `dst_service`, `namespace` | Counter | P0 |
| 5.1.5 | `kerno_tcp_connections_total` | `src_pod`, `dst_service`, `namespace`, `state` | Counter | P0 |
| 5.1.6 | `kerno_oom_kills_total` | `pod`, `namespace`, `node` | Counter | P0 |
| 5.1.7 | `kerno_memory_pressure_ratio` | `pod`, `namespace`, `node` | Gauge | P0 |
| 5.1.8 | `kerno_disk_io_duration_nanoseconds` | `device`, `operation`, `quantile` | Summary | P0 |
| 5.1.9 | `kerno_sched_delay_nanoseconds` | `process`, `namespace`, `pod`, `quantile` | Summary | P0 |
| 5.1.10 | `kerno_fd_open_total` | `process`, `namespace`, `pod` | Gauge | P1 |
| 5.1.11 | `kerno_file_access_total` | `file`, `process`, `pod`, `namespace`, `operation` | Counter | P1 |
| 5.1.12 | `kerno_collector_events_total` | `collector` | Counter | P0 |
| 5.1.13 | `kerno_collector_errors_total` | `collector` | Counter | P0 |
| 5.1.14 | `kerno_bpf_programs_loaded` | - | Gauge | P0 |

### 5.2 Implementation

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 5.2.1 | Prometheus client registry with `kerno_` prefix | P0 | `prometheus/client_golang` |
| 5.2.2 | HTTP server for `/metrics` + `/healthz` + `/readyz` | P0 | |
| 5.2.3 | Label cardinality guard: cap unique label combinations per metric | P0 | Prevent OOM from runaway labels |
| 5.2.4 | Self-monitoring metrics: BPF ring buffer drops, CPU overhead estimate | P0 | |
| 5.2.5 | ServiceMonitor manifest for Prometheus Operator | P1 | |

### Definition of Done - Phase 5

- [x] `curl localhost:9090/metrics` returns valid Prometheus exposition format
- [ ] Grafana can query and graph kerno metrics
- [ ] Label cardinality stays under 10K combinations under load
- [x] Self-monitoring: `kerno_collector_events_total` tracks throughput

---

## Phase 6 - Environment Adapters *(Week 8–9)*

> **Goal:** Every event is automatically enriched with environment context.

### 6.1 Adapter Interface

```go
type Adapter interface {
    Name() string
    Enrich(event *Event) // Mutates event in place with env metadata
    Start(ctx context.Context) error
    Stop()
}
```

### 6.2 Implementations

| # | Adapter | Enrichment Source | Priority |
|---|---------|-------------------|----------|
| 6.2.1 | **BareMetalAdapter** | hostname, cgroup path, PID → comm | P0 | Always active |
| 6.2.2 | **KubernetesAdapter** | cgroup path → pod name, namespace, node, labels, deployment | P0 | Uses K8s informer with local cache |
| 6.2.3 | **SystemdAdapter** | cgroup path → systemd unit, slice, scope | P1 | Parses cgroup v2 path |
| 6.2.4 | **DetectEnvironment()** auto-detection: check for K8s token, then systemd, fallback to bare metal | P0 | |

### 6.3 Kubernetes Adapter Detail

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 6.3.1 | `SharedIndexInformer` for Pods - local cache, zero hot-path API calls | P0 | |
| 6.3.2 | cgroup path → pod UID mapping (parse `kubepods/burstable/pod<uid>/...`) | P0 | Must handle cgroup v1 and v2 |
| 6.3.3 | Pod cache warming with backoff retry | P0 | Don't crash if API server slow on startup |
| 6.3.4 | Label-based filtering: only enrich pods matching selector | P2 | Reduce work on large clusters |

### Definition of Done - Phase 6

- [x] On K8s: every event has `pod`, `namespace`, `node`, `deployment` fields
- [x] On bare metal: every event has `hostname`, `cgroup`, `comm` fields
- [x] On systemd: events from services have `unit` field (e.g., `nginx.service`)
- [ ] K8s adapter uses <10MB memory for 1000-pod cluster
- [x] Adapter auto-detection works correctly in DaemonSet and on bare VM

---

## Phase 7 - Kubernetes Deployment *(Week 9–10)*

> **Goal:** `helm install kerno lowplane/kerno` works end-to-end on a real cluster.

### 7.1 Manifests

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 7.1.1 | Namespace manifest: `kerno-system` | P0 | |
| 7.1.2 | DaemonSet manifest (as specified in idea.md §8.2) | P0 | `hostPID`, `hostNetwork`, `privileged` |
| 7.1.3 | RBAC: ServiceAccount + ClusterRole + ClusterRoleBinding (as in idea.md §8.3) | P0 | Minimal permissions |
| 7.1.4 | Service for Prometheus scraping (ClusterIP, port 9090) | P0 | |
| 7.1.5 | ServiceMonitor for Prometheus Operator (optional) | P1 | |
| 7.1.6 | PodDisruptionBudget | P1 | |

### 7.2 Helm Chart

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 7.2.1 | `Chart.yaml` with proper metadata, appVersion, dependencies | P0 | |
| 7.2.2 | `values.yaml` matching idea.md §8.4 spec | P0 | |
| 7.2.3 | All manifests templatized (image, resources, tolerations, nodeSelector, affinity) | P0 | |
| 7.2.4 | Optional components gated by values: SLO CRD, KEDA scaler, Incident CRD, sinks | P0 | |
| 7.2.5 | `helm test` with connection test pod | P1 | |
| 7.2.6 | Publish to Artifact Hub | P2 | |

### 7.3 Docker Image

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 7.3.1 | Multi-stage Dockerfile: build with Go + clang → runtime with distroless/static | P0 | |
| 7.3.2 | Multi-arch manifest: linux/amd64, linux/arm64 | P1 | |
| 7.3.3 | Image signing with cosign | P2 | Supply chain security |
| 7.3.4 | SBOM generation | P2 | |

### Definition of Done - Phase 7

- [ ] `helm install kerno ./deploy/helm/kerno -n kerno-system --create-namespace` works
- [ ] DaemonSet runs on all nodes (including control-plane with tolerations)
- [ ] `curl <kerno-pod-ip>:9090/metrics` returns metrics with pod labels
- [ ] `kubectl logs -n kerno-system <kerno-pod>` shows structured JSON logs
- [ ] `helm upgrade` with changed values works without data loss

---

## Phase 7.5 - Bare-Metal, VM & Systemd Deployment *(Week 10)*

> **Goal:** `curl -sfL https://get.kerno.sh | sudo bash` installs kerno on any Linux. `sudo kerno doctor` works on bare metal, VMs (EC2, GCE, Azure), and systemd-managed servers without any Kubernetes dependency. **Bare-metal is not a secondary target - every rule that ships must work here too.**

### 7.5.1 - Install & Packaging

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 7.5.1.1 | **`scripts/install.sh`** - one-liner installer: detect arch, download from GitHub Releases, install to `/usr/local/bin/kerno`, optional `--daemon` flag for systemd | P0 | ✅ Created |
| 7.5.1.2 | **`deploy/systemd/kerno.service`** - hardened systemd unit with AmbientCapabilities, ProtectSystem, MemoryMax, journal logging | P0 | ✅ Created |
| 7.5.1.3 | **`deploy/systemd/kerno.yaml`** - default config for `/etc/kerno/config.yaml` | P0 | ✅ Created |
| 7.5.1.4 | goreleaser produces `kerno_<ver>_linux_amd64.tar.gz` and `kerno_<ver>_linux_arm64.tar.gz` | P0 | Release artifacts the installer downloads |
| 7.5.1.5 | `.deb` package via goreleaser nfpm (Ubuntu/Debian: `sudo apt install ./kerno.deb`) | P1 | Includes systemd unit + default config |
| 7.5.1.6 | `.rpm` package via goreleaser nfpm (Fedora/RHEL/Amazon Linux) | P1 | |
| 7.5.1.7 | `brew install lowplane/tap/kerno` - Homebrew tap for Linux (and macOS dev, CLI-only) | P2 | |
| 7.5.1.8 | Host `get.kerno.sh` as a GitHub Pages redirect to `scripts/install.sh` | P0 | Branded install URL |

### 7.5.2 - Bare-Metal / VM Collector Compatibility

> **Invariant:** Every v0.2 rule must either (a) work on bare metal or (b) gracefully return nil and skip.

| # | Rule | Bare Metal | VM (EC2/GCE) | Notes |
|---|------|:---:|:---:|---|
| 7.5.2.1 | Rules 1–11 (existing eBPF + procfs) | ✅ | ✅ | Pure kernel - works everywhere with BTF |
| 7.5.2.2 | `cpu_throttled` (cgroup cpu.stat) | ⚠️ nil | ⚠️ nil | Only fires when cgroup v2 CPU limits are set. On bare metal without containers, returns nil - no false positive. |
| 7.5.2.3 | `memory_limit_pressure` (cgroup memory.*) | ⚠️ nil | ⚠️ nil | Same - only fires with cgroup memory limits. |
| 7.5.2.4 | `crash_loop` (/proc process tracking) | ✅ | ✅ | Tracks any rapid-restart process, not just pods |
| 7.5.2.5 | `disk_space_critical` (statfs) | ✅ | ✅ | Checks all mount points |
| 7.5.2.6 | `conntrack_exhaustion` (/proc/sys/net) | ✅ if nf_conntrack loaded | ✅ | Returns nil if conntrack module not loaded |
| 7.5.2.7 | `cpu_steal_high` (/proc/stat) | N/A (steal=0) | ✅ | steal is always 0 on bare metal - rule returns nil, no noise |
| 7.5.2.8 | `node_memory_pressure` (/proc/meminfo) | ✅ | ✅ | On bare metal: uses default thresholds (100Mi available). No kubelet config to read. |
| 7.5.2.9 | `swap_thrashing` (/proc/vmstat) | ✅ | ✅ | Works everywhere |
| 7.5.2.10 | `nic_errors` (/sys/class/net) | ✅ | ✅ | Works everywhere |

**Result: 18 of 20 rules work on bare metal. 2 rules (cgroup throttle) gracefully skip. Zero false positives.**

### 7.5.3 - Systemd Enrichment (VM-specific value)

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 7.5.3.1 | Systemd adapter enriches findings with unit name: "nginx.service is experiencing high syscall latency" | P0 | Already implemented in `internal/adapter/systemd.go` |
| 7.5.3.2 | Doctor findings on systemd show `Unit:` field instead of `Pod:` | P0 | Adapt renderer to environment |
| 7.5.3.3 | `kerno doctor --unit nginx.service` - filter findings to a specific systemd unit | P1 | Equivalent of `--namespace` for bare metal |
| 7.5.3.4 | `kerno doctor --pid 1234` - diagnose a specific process | P1 | Useful for debugging any Linux process |

### 7.5.4 - VM Cloud Provider Enrichment

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 7.5.4.1 | Auto-detect cloud provider from SMBIOS/DMI: `cat /sys/class/dmi/id/board_vendor` (AWS, Google, Microsoft) | P1 | "Running on AWS EC2 (i3.xlarge)" in report header |
| 7.5.4.2 | Instance type detection: read from instance metadata (`169.254.169.254`) or DMI | P2 | Helps with "is this instance undersized?" suggestions |
| 7.5.4.3 | `cpu_steal_high` fix suggestion on cloud: "Consider a larger instance or dedicated host" | P0 | Actionable advice for VM users |

### Definition of Done - Phase 7.5

- [ ] `curl -sfL https://get.kerno.sh | sudo bash` installs a working binary on Ubuntu 22.04 + Fedora 39 + Amazon Linux 2023
- [ ] `curl -sfL https://get.kerno.sh | sudo bash -s -- --daemon` also installs and starts the systemd service
- [ ] `sudo kerno doctor` on a bare-metal server with no containers produces a correct report (no false positives from cgroup rules)
- [ ] `sudo kerno doctor` on an EC2 instance detects CPU steal time when present
- [ ] `systemctl status kerno` shows active + healthy after daemon install
- [ ] `journalctl -u kerno -f` shows structured JSON logs
- [ ] Findings on systemd hosts show unit names (e.g., `nginx.service`), not PIDs

---

## Phase 8 - README & Demo *(Week 10)*

> **Goal:** The README is the marketing page. It must make an engineer star the repo in 15 seconds.

### 8.1 README Structure

| # | Section | Priority | Notes |
|---|---------|----------|-------|
| 8.1.1 | Hero: one-sentence tagline + badge row (CI, Go Report, License, Release) | P0 | |
| 8.1.2 | **Demo GIF** - terminal recording of `kerno doctor` on a stressed system | P0 | **THE most important asset** |
| 8.1.3 | "What is Kerno?" - 3-sentence explanation | P0 | |
| 8.1.4 | Quickstart: 3 commands (install → run → see output) | P0 | |
| 8.1.5 | Feature matrix table (Kerno vs others - from idea.md §1) | P0 | Immediate differentiation |
| 8.1.6 | How it works diagram (ASCII art from idea.md §3) | P0 | |
| 8.1.7 | CLI examples for each major command | P0 | Copy-paste friendly |
| 8.1.8 | Kubernetes deployment (Helm one-liner) | P0 | |
| 8.1.9 | Architecture link (→ docs/architecture.md) | P1 | |
| 8.1.10 | Contributing link | P0 | |
| 8.1.11 | License footer | P0 | |

### 8.2 Demo Recording - *the single most important deliverable*

> **Treat this like a P0 feature, not a P0 chore.** Per principle #8, the demo GIF is the viral asset. Spend a full week on it. The architecture won't go viral; the screenshot will. Budget: ~20% of total project effort goes here, alone, before Phase 9.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 8.2.1 | `scripts/stress-test.sh` - reproducibly induces a real cascade: disk fsync saturation → DB write delay → upstream API p99 → user-facing error | P0 | `stress-ng`, `tc netem`, `fio`. Must produce signal patterns that exercise the causal timeline (Phase 14.2) |
| 8.2.2 | `scripts/k8s-stress.sh` - same cascade inside a kind cluster, so the K8s demo GIF is just as compelling | P0 | |
| 8.2.3 | `demo.tape` (VHS config) for reproducible GIF - checked into the repo so anyone can re-record | P0 | `charmbracelet/vhs` |
| 8.2.4 | Record `kerno doctor` GIF: stressed VM, finding the cascade, showing the causal timeline. 1000×600, Dracula theme, 13pt, ≤30s | P0 | **The hero asset** |
| 8.2.5 | Record `kubectl kerno doctor` GIF: same cascade in a kind cluster, cluster-level report | P0 | The K8s hero asset |
| 8.2.6 | Record `kerno doctor --watch` GIF: early signal warning firing 60s before the breach | P1 | Secondary asset |
| 8.2.7 | Optimize all GIFs to <5 MB with `gifsicle --optimize=3` for fast GitHub rendering | P0 | |
| 8.2.8 | Re-record cadence: every Phase that changes doctor output must re-record. Add to `make demo` target. | P0 | Prevents demo drift |

### 8.3 Landing Page & Launch

> **Goal:** When the GIF goes viral, send people somewhere. The README is for engineers who already clicked; the landing page is for everyone else.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 8.3.1 | One-page static site at `kerno.lowplane.dev`: hero GIF, one-sentence pitch, install command, "Why Kerno" section, link to GitHub | P0 | Plain HTML or Astro - no SPA |
| 8.3.2 | Hero copy: lead with the *incident*, not the *kernel*. Test variants: "When something breaks in production, run one command." / "Production incidents, root cause in 30 seconds." | P0 | Match Principle #7 positioning |
| 8.3.3 | "How it works in 30 seconds" - three steps with screenshots, no architecture diagrams above the fold | P0 | |
| 8.3.4 | Install widget: tab between `curl \| sh`, `brew`, `helm install`, `kubectl krew install` | P0 | |
| 8.3.5 | Email capture for v0.1 launch list (not a feature, a marketing asset) | P1 | |
| 8.3.6 | Hosted on GitHub Pages or Cloudflare Pages - zero infra | P0 | |

### 8.4 Launch Checklist (run once before v0.1)

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 8.4.1 | HN post draft: "Show HN: Kerno - eBPF root-cause for production incidents" with the demo GIF embedded | P0 | Post Tuesday 9am PT |
| 8.4.2 | Twitter / X thread: 5 tweets, each with one screenshot from a different finding type | P0 | |
| 8.4.3 | r/sre, r/kubernetes, r/devops cross-posts | P1 | Not all at once - stagger by 2 days |
| 8.4.4 | Lobste.rs submission with `eBPF, observability` tags | P1 | |
| 8.4.5 | Personal LinkedIn / network outreach for first 100 stars | P1 | |
| 8.4.6 | Post-launch: monitor GitHub issues + HN comments for the first 24h, respond fast | P0 | Engagement window matters more than the post itself |

### 8.5 Chaos Injector & One-Liner Installers *(pre-launch enablers)*

> **Goal:** Make the demo reliably reproducible, and make "try it right now" a 5-second operation. Both directly feed Phase 8.2 and Phase 18.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 8.5.1 | `kerno chaos --induce fd-leak\|oom\|disk-sat\|runqueue\|cascade` - synthetic failure injector in `internal/chaos/`. Not a toy - it's the "prove it works" button, the demo recorder, and a CI gate all at once. | P0 | Isolated subcommand; never auto-runs. Exits after N seconds or SIGINT. |
| 8.5.2 | `kerno chaos --list` shows available scenarios with one-line descriptions | P1 | Self-documenting |
| 8.5.3 | Each chaos scenario must be pairable with a doctor rule - so the GIF shows induce → detect → explain end-to-end | P0 | Integration test per pair |
| 8.5.4 | `curl -sfL https://get.kerno.sh \| bash` - one-liner installer (static binary from GitHub releases, verified with cosign) | P0 | Host the script as a GitHub Pages file in the `lowplane/kerno` repo |
| 8.5.5 | `kubectl apply -f https://kerno.sh/install.yaml` - single-file install for any cluster | P0 | Points at the Helm chart rendered output |
| 8.5.6 | `brew install lowplane/tap/kerno` - Homebrew tap for Mac dev users | P1 | Post-launch is fine |
| 8.5.7 | Install widget on the landing page (Phase 8.3.4) pulls from the *same* canonical commands - no drift | P0 | Single source of truth |

**Definition of Done - Phase 8.5**
- [ ] `kerno chaos --induce cascade` reliably triggers every signal the causal timeline consumes
- [ ] `curl -sfL https://get.kerno.sh \| bash` produces a working `kerno` binary on Ubuntu 22.04 + Fedora 39
- [ ] `kubectl apply -f https://kerno.sh/install.yaml` deploys a working DaemonSet on kind + EKS + GKE

### Definition of Done - Phase 8

- [ ] README renders beautifully on GitHub
- [ ] Three GIFs recorded: `kerno doctor`, `kubectl kerno doctor`, `kerno doctor --watch`
- [ ] All GIFs show the **causal timeline** clearly - that's the new and shareable bit
- [ ] Landing page live at `kerno.lowplane.dev` with the hero GIF and install widget
- [ ] HN post draft + Twitter thread written and ready to publish
- [ ] A new visitor understands what Kerno is and how to try it within 30 seconds
- [ ] Quickstart works on a fresh Ubuntu 22.04 VM following README instructions alone

---

## Phase 9 - Hardening & Testing *(Week 10–12)*

> **Goal:** Production-safe. If someone deploys Kerno on prod nodes, it won't cause problems.

### 9.1 Testing Strategy

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 9.1.1 | Unit tests for all aggregation math (histograms, percentiles, rates) | P0 | Table-driven |
| 9.1.2 | Unit tests for all doctor rules (inject mock signals → verify findings) | P0 | |
| 9.1.3 | Unit tests for renderers (snapshot → verify output format) | P0 | |
| 9.1.4 | Unit tests for config parsing and validation | P0 | |
| 9.1.5 | Unit tests for K8s adapter cgroup-to-pod parsing | P0 | |
| 9.1.6 | Integration tests: load eBPF, trigger events, read from ringbuf | P1 | Requires root + kernel |
| 9.1.7 | Fuzz tests for binary event parsing (Go fuzzing) | P1 | Prevent crashes from malformed events |
| 9.1.8 | Benchmark tests for hot-path aggregation | P1 | `testing.B` |
| 9.1.9 | Target: **≥80% unit test coverage** | P0 | |

### 9.2 Reliability

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 9.2.1 | Ring buffer overflow handling: count drops, don't crash | P0 | Metric: `kerno_ringbuf_drops_total` |
| 9.2.2 | BPF program load failure: clear error + fallback (skip that collector) | P0 | "syscall collector unavailable: kernel too old" |
| 9.2.3 | Memory limit: hard cap on per-collector memory via bounded data structures | P0 | |
| 9.2.4 | CPU limit: rate-limit event processing if exceeding budget | P1 | |
| 9.2.5 | Graceful shutdown: drain ring buffers, close BPF links, flush metrics | P0 | |
| 9.2.6 | Health endpoint: `/healthz` → BPF programs loaded, `/readyz` → collectors running | P0 | K8s probes |

### 9.3 Security

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 9.3.1 | Document exact capabilities needed (CAP_BPF, CAP_PERFMON, CAP_SYS_PTRACE) | P0 | |
| 9.3.2 | Don't log sensitive data (file contents, environment variables, auth tokens) | P0 | |
| 9.3.3 | Validate all user inputs in CLI and config | P0 | |
| 9.3.4 | Rate-limit Prometheus label creation to prevent cardinality bombs | P0 | |
| 9.3.5 | Pin BPF map sizes to prevent kernel memory exhaustion | P0 | |

### 9.4 Performance Benchmarks

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 9.4.1 | Measure CPU overhead at 10K, 100K, 1M events/sec | P0 | Target: <1% CPU at 100K/s |
| 9.4.2 | Measure memory usage under sustained load | P0 | Target: <128MB RSS |
| 9.4.3 | Measure syscall latency added by kprobes/tracepoints | P0 | Target: <1μs per hook |
| 9.4.4 | Publish results in `docs/performance.md` | P1 | Build trust |

### Definition of Done - Phase 9

- [ ] ≥80% unit test coverage
- [ ] No panics under fuzz testing (1 hour run)
- [ ] Sustained 100K events/s with <1% CPU on 4-core machine
- [ ] Memory stays <128MB RSS after 1 hour sustained load
- [ ] Graceful shutdown completes within 5 seconds
- [ ] All health/readiness probes work

---

## Phase 10 - Complete Signal Coverage *(Month 3–4)* 🔴 CRITICAL GAP

> **Goal:** Kerno claims to be a system-level incident diagnosis engine. Right now it detects 6 signal types but misses dozens of common production incidents. This phase closes every major detection gap so `kerno doctor` can credibly diagnose **most** system-level incidents on Kubernetes and Linux. Without this, we're a demo - not a product.
>
> **Principle:** Every eBPF program below gets a Go loader, a collector, at least one doctor rule, and a test. No orphan signals.

### 10.1 - Cgroup Resource Limit Detection *(K8s #1 pain point)*

> **Why this is first:** On Kubernetes, the #1 mystery incident is "my pod is slow but I don't know why." The answer is almost always cgroup throttling - CPU limits, memory limits, or I/O bandwidth limits imposed by the kubelet. Kerno currently captures cgroup IDs but does NOTHING with them. This is the single biggest gap for K8s credibility.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.1.1 | **New eBPF program: `cgroup_pressure.c`** - attach to cgroup pressure stall information (PSI) tracepoints: `psi/psi_memstall`, `psi/psi_cpustall`, `psi/psi_iostall` (kernel 5.13+) | P0 | PSI gives "how long are tasks stalled waiting for CPU/memory/IO?" - direct measure of cgroup pain |
| 10.1.2 | **CPU throttling detector:** read `cpu.stat` (nr_throttled, throttled_usec) from cgroup v2 fs per-container. No eBPF needed - poll `/sys/fs/cgroup/` every 5s | P0 | "Your pod was throttled for 3.2s out of the last 10s" - #1 K8s mystery solved |
| 10.1.3 | **Memory limit detector:** read `memory.events` (max, oom, oom_kill, oom_group_kill) from cgroup v2. Watch `memory.current` vs `memory.max` | P0 | Detect "container is 98% of its memory limit and growing" - predict OOMKill before it happens |
| 10.1.4 | **I/O throttle detector:** read `io.stat` and `io.pressure` from cgroup v2 | P1 | Detect "container I/O is being throttled by BPS/IOPS limits" |
| 10.1.5 | **PID limit detector:** read `pids.current` vs `pids.max` from cgroup v2 | P1 | Detect "container is about to hit PID limit (fork bomb, thread leak)" |
| 10.1.6 | **CgroupCollector** Go implementation: polls cgroup v2 filesystem, builds `CgroupSnapshot` with per-container throttle stats | P0 | New `internal/collector/cgroup/` |
| 10.1.7 | **Doctor rule: `cpu_throttled`** - fires CRITICAL when nr_throttled > X in window, with exact throttle percentage | P0 | "payment-api lost 32% of its CPU time to cgroup throttling. Increase CPU limit or reduce usage." |
| 10.1.8 | **Doctor rule: `memory_limit_pressure`** - fires WARNING at 85%, CRITICAL at 95% of cgroup memory.max, with growth rate + ETA to OOMKill | P0 | Distinct from system-wide OOM - this is per-container |
| 10.1.9 | **Doctor rule: `io_throttled`** - fires WARNING when I/O pressure exceeds 25% (task stall time) | P1 | |
| 10.1.10 | **Doctor rule: `pid_exhaustion`** - fires WARNING when pids.current > 80% of pids.max | P1 | |
| 10.1.11 | **Cgroup-to-pod mapper:** resolve cgroup path → (pod name, namespace, container name) using `/proc/<pid>/cgroup` + K8s downward API or kubelet API | P0 | Foundation for all K8s-context enrichment |

### 10.2 - DNS Resolution Failures *(K8s #2 pain point)*

> **Why:** Slow or failing DNS is the silent killer on Kubernetes. CoreDNS hiccups cause cascading timeouts across every service. Currently Kerno monitors zero UDP traffic.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.2.1 | **New eBPF program: `dns_monitor.c`** - attach to `udp_sendmsg` and `udp_recvmsg` (or `tracepoint/net/net_dev_xmit` + `tracepoint/net/netif_receive_skb`). Filter on destination port 53. Parse DNS header to extract query name, type, response code, latency | P0 | Lightweight: only capture DNS packets, not all UDP |
| 10.2.2 | **DNSCollector** Go implementation: tracks per-query latency (P50/P95/P99), NXDOMAIN rate, SERVFAIL rate, timeout rate, top slow queries | P0 | New `internal/collector/dns/` |
| 10.2.3 | **Doctor rule: `dns_resolution_slow`** - fires WARNING if DNS P99 > 100ms, CRITICAL if > 500ms | P0 | "DNS resolution is taking 340ms P99 - CoreDNS may be overloaded or upstream resolver is slow" |
| 10.2.4 | **Doctor rule: `dns_failure_rate`** - fires WARNING if NXDOMAIN+SERVFAIL rate > 1%, CRITICAL if > 5% | P0 | "12% of DNS queries are failing (SERVFAIL). Check CoreDNS pods." |
| 10.2.5 | **Doctor rule: `dns_timeout`** - fires CRITICAL if DNS timeout rate > 0.5% | P0 | "DNS queries are timing out. This causes cascading connection failures in all services." |
| 10.2.6 | Enrich DNS data with pod context: which pods are making slow/failing DNS queries | P0 | "checkout-api is experiencing 89% of the DNS failures" |

### 10.3 - TCP Connection Failures *(currently blind to RST, timeout, refused)*

> **Why:** Current TCP monitor only tracks ESTABLISHED and CLOSE. It misses connection refused, connection reset, connection timeout - the most common network failures in production.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.3.1 | **Expand `tcp_monitor.c`:** capture ALL TCP state transitions, not just ESTABLISHED/CLOSE. Track SYN_SENT→CLOSE (refused), ESTABLISHED→CLOSE_WAIT (reset), timeout durations | P0 | Currently lines 62-66 filter out everything except ESTABLISHED/CLOSE |
| 10.3.2 | **New eBPF hook: `tcp_drop`** tracepoint (kernel ≥5.17) or `kfree_skb_reason` - captures every dropped TCP packet with the kernel's reason code | P0 | "342 packets dropped: reason=NO_SOCKET (connection refused)" |
| 10.3.3 | **IPv6 support:** remove the `AF_INET` filter in `tcp_monitor.c` line 23. Add `struct in6_addr` handling | P0 | Critical for any modern K8s cluster (dual-stack is default now) |
| 10.3.4 | **SYN backlog overflow detector:** track `tcp_req_err` or read `/proc/net/netstat` for `ListenOverflows` | P1 | "Server is dropping incoming connections - SYN backlog full" |
| 10.3.5 | **Doctor rule: `tcp_connection_failures`** - fires when connection refused/reset/timeout rate exceeds threshold | P0 | |
| 10.3.6 | **Doctor rule: `tcp_drops`** - fires when kernel is dropping packets, with reason breakdown | P0 | |
| 10.3.7 | **Doctor rule: `tcp_backlog_overflow`** - fires when listen backlog is full | P1 | "Service is refusing connections because accept queue is full" |
| 10.3.8 | **Connection tracking:** maintain per-(src_pod, dst_pod, dst_port) connection state table with success/fail/reset counts | P0 | Foundation for service dependency mapping |

### 10.4 - Memory Collector & Page Fault Tracking *(currently broken)*

> **Why:** The `oom_imminent` rule exists but the Memory collector is NOT implemented. Memory is 50% of all production incidents.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.4.1 | **MemoryCollector implementation:** poll `/proc/meminfo` every 1s for system-wide memory. Parse MemTotal, MemAvailable, Buffers, Cached, SwapTotal, SwapFree, Dirty, Writeback | P0 | No eBPF needed - procfs is the right source |
| 10.4.2 | **Per-process RSS tracking:** read `/proc/<pid>/statm` for top-N memory consumers, track growth rate | P0 | "postgres RSS grew from 2.1GB to 3.8GB in the last 5 minutes" |
| 10.4.3 | **New eBPF program: `page_fault.c`** - attach to `tracepoint/exceptions/page_fault_user` and `page_fault_kernel`. Track major vs minor fault rate per process | P0 | Major page faults = thrashing indicator |
| 10.4.4 | **Swap activity monitor:** track swap-in/swap-out rate from `/proc/vmstat` (pswpin, pswpout) | P0 | "System is swapping 450MB/s - severe memory pressure" |
| 10.4.5 | **Doctor rule: `memory_pressure`** (fix existing): wire up to real MemoryCollector data | P0 | Currently a dead rule - never fires with real data |
| 10.4.6 | **Doctor rule: `swap_thrashing`** - fires WARNING when swap activity > 10MB/s, CRITICAL > 100MB/s | P0 | |
| 10.4.7 | **Doctor rule: `page_fault_storm`** - fires WARNING when major page faults > 1000/s per process | P0 | Detects thrashing, mmap abuse, memory-mapped I/O contention |
| 10.4.8 | **Doctor rule: `memory_leak_detected`** - fires when a process RSS grows monotonically > 10MB/min for 5+ minutes | P1 | Per-process leak detection with growth rate |
| 10.4.9 | **NUMA-aware memory tracking:** read `/sys/devices/system/node/nodeN/meminfo` for multi-socket systems | P2 | "Remote NUMA memory access is 40% of total - consider CPU pinning" |

### 10.5 - Lock Contention & Application Stalls *(invisible killer)*

> **Why:** "My app is slow but CPU is low" is almost always lock contention - futex waits, mutex spins, or kernel-level lock holds. Nobody detects this from outside the process. Kerno can.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.5.1 | **New eBPF program: `lock_contention.c`** - attach to `tracepoint/lock/contention_begin` + `contention_end` (kernel ≥5.17). Track lock hold time, wait time, lock address, caller | P0 | Direct measure of "how long are threads waiting for locks?" |
| 10.5.2 | **Futex tracker:** attach to `tracepoint/syscalls/sys_enter_futex` + `sys_exit_futex`. Track futex wait duration per process | P0 | User-space mutex contention (Go mutexes, pthread_mutex, Java synchronized) |
| 10.5.3 | **LockCollector** Go implementation: aggregates per-process lock contention time, top contended locks | P0 | New `internal/collector/lock/` |
| 10.5.4 | **Doctor rule: `lock_contention_high`** - fires WARNING when > 10% of CPU time spent waiting on locks, CRITICAL > 30% | P0 | "postgres is spending 22% of its time waiting on locks - likely connection pool contention" |
| 10.5.5 | **Doctor rule: `futex_storm`** - fires when futex wait rate > 10K/s per process | P1 | Detects thundering herd, lock convoy |
| 10.5.6 | Graceful fallback: if kernel < 5.17 (no lock tracepoints), use futex-only tracking | P0 | Works on all kernels ≥ 5.8 |

### 10.6 - Network Socket & Buffer Issues *(TCP is not enough)*

> **Why:** TCP retransmits tell you the network is bad. But socket buffer overflows, connection queue exhaustion, and ephemeral port exhaustion cause equally mysterious failures.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.6.1 | **Socket buffer overflow detector:** attach to `tracepoint/sock/sock_rcvqueue_full` or monitor `/proc/net/sockstat` for drops | P0 | "Receive buffer overflow on postgres socket - data being dropped" |
| 10.6.2 | **Ephemeral port exhaustion:** monitor `/proc/sys/net/ipv4/ip_local_port_range` usage via `/proc/net/tcp` count | P0 | "87% of ephemeral ports in use - new connections will fail in ~30s" |
| 10.6.3 | **CONNTRACK table exhaustion:** read `/proc/sys/net/nf_conntrack_count` vs `nf_conntrack_max` | P0 | K8s uses conntrack for services. Full table = invisible packet drops |
| 10.6.4 | **Doctor rule: `socket_buffer_overflow`** - fires when receive queue drops detected | P0 | |
| 10.6.5 | **Doctor rule: `ephemeral_port_exhaustion`** - fires WARNING at 70%, CRITICAL at 85% | P0 | "Ephemeral port exhaustion imminent. ETA: 45 seconds. Fix: check for connection leaks." |
| 10.6.6 | **Doctor rule: `conntrack_exhaustion`** - fires WARNING at 75%, CRITICAL at 90% of nf_conntrack_max | P0 | "Conntrack table 92% full. New K8s service connections will be silently dropped." |
| 10.6.7 | **Netfilter/iptables drop counter:** read `/proc/net/stat/nf_conntrack` or attach to `nf_hook_slow` | P1 | Detect iptables/netfilter rule drops in K8s networking |

### 10.7 - Kernel Health & Stability *(predict crashes before they happen)*

> **Why:** Soft lockups, RCU stalls, and kernel warnings are precursors to system crashes. No userspace tool detects these. Kerno can.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.7.1 | **New eBPF program: `kernel_health.c`** - attach to `tracepoint/printk/console` and filter for `BUG:`, `WARNING:`, `soft lockup`, `RCU`, `hung_task` | P0 | Catches kernel warnings before they become panics |
| 10.7.2 | **Softirq/IRQ storm detector:** attach to `tracepoint/irq/softirq_entry` + `softirq_exit`. Track per-CPU softirq time | P1 | "CPU 3 spending 67% of time in NET_RX softirq - network interrupt storm" |
| 10.7.3 | **Hung task detector:** watch for `hung_task_timeout_secs` kernel messages via printk tracepoint | P0 | "Process postgres stuck in uninterruptible sleep for 120s" |
| 10.7.4 | **Doctor rule: `kernel_warning`** - fires CRITICAL on any `BUG:` or `soft lockup`, WARNING on `WARNING:` | P0 | "Kernel soft lockup detected on CPU 2 - system may become unresponsive" |
| 10.7.5 | **Doctor rule: `irq_storm`** - fires when any CPU spends > 50% time in softirq processing | P1 | |
| 10.7.6 | **Doctor rule: `hung_task`** - fires CRITICAL when a task is stuck in D state > 30s | P0 | |
| 10.7.7 | **Dmesg parser fallback:** for kernels where printk tracepoint isn't available, parse `/dev/kmsg` from userspace | P0 | Graceful degradation |

### 10.8 - Filesystem & Storage Deep Diagnostics *(beyond block I/O)*

> **Why:** Current disk_io.c watches block layer only. Filesystem-level issues (journal contention, inode exhaustion, NFS hangs, writeback pressure) are invisible.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.8.1 | **Inode/dentry cache pressure:** read `/proc/sys/fs/inode-nr`, `/proc/sys/fs/dentry-state`, `/proc/sys/fs/file-nr` | P0 | "Filesystem has 98% inodes used - new file creation will fail" |
| 10.8.2 | **Writeback pressure detector:** read `/proc/vmstat` (nr_dirty, nr_writeback, nr_writeback_temp) | P0 | "Dirty page writeback backlog is 2.1GB - fsync calls will block" |
| 10.8.3 | **NFS latency detector:** attach to `tracepoint/nfs/nfs_readpage_done` + `nfs_writeback_done` or poll `/proc/self/mountstats` | P1 | "NFS server 10.0.1.5 response time is 3.2s - mount is effectively hung" |
| 10.8.4 | **Disk space monitor:** check mount points for > 90% usage (especially ephemeral storage on K8s) | P0 | "Node ephemeral storage 94% full - pods will be evicted" |
| 10.8.5 | **Per-device I/O stats:** read `/sys/block/<dev>/stat` for queue depth, IOPS, bandwidth per device | P0 | "Device nvme0n1: queue depth 128 (saturated), 45K IOPS" |
| 10.8.6 | **Doctor rule: `inode_exhaustion`** - fires when free inodes < 5% | P0 | |
| 10.8.7 | **Doctor rule: `writeback_pressure`** - fires when dirty pages > 20% of RAM or writeback queue > 1GB | P0 | |
| 10.8.8 | **Doctor rule: `nfs_hang`** - fires when NFS latency > 1s | P1 | |
| 10.8.9 | **Doctor rule: `disk_space_critical`** - fires WARNING at 85%, CRITICAL at 95% per mount | P0 | Includes ephemeral storage for K8s pod eviction prediction |
| 10.8.10 | **Doctor rule: `disk_queue_saturated`** - fires when avgqu-sz > configured threshold per device | P0 | |

### 10.9 - Process & Container Lifecycle *(K8s crash loop detection)*

> **Why:** CrashLoopBackOff is the #1 most-googled K8s error. Kerno sees the kernel-level signals that cause it (SIGSEGV, SIGKILL, exit codes) but currently ignores process lifecycle entirely.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.9.1 | **New eBPF program: `process_lifecycle.c`** - attach to `tracepoint/sched/sched_process_exit`. Capture exit code, signal number, PID, comm, runtime duration | P0 | Sees every process death in real time |
| 10.9.2 | **Process crash tracker:** detect rapid restart patterns (same comm dying > 3 times in 5 minutes) | P0 | Kernel-level CrashLoopBackOff detection - faster than kubelet |
| 10.9.3 | **Signal-kill tracker:** detect SIGKILL (from OOM, cgroup, manual), SIGSEGV (crash), SIGABRT (assertion) patterns | P0 | "postgres-0 killed by SIGKILL 4 times in 2 minutes (cgroup OOM)" |
| 10.9.4 | **Fork bomb detector:** track fork rate per cgroup. Fire when fork rate > 1000/s | P1 | |
| 10.9.5 | **Doctor rule: `crash_loop`** - fires CRITICAL when a process restarts > 3 times in 5 minutes | P0 | "checkout-api has restarted 7 times in 3 minutes. Exit code: 137 (SIGKILL). Likely cause: cgroup memory limit exceeded." |
| 10.9.6 | **Doctor rule: `signal_storm`** - fires when abnormal signal rate (SIGSEGV, SIGBUS, SIGFPE) > 0 in window | P0 | "3 SIGSEGV signals in payment-api - segmentation fault, likely memory corruption or null pointer" |
| 10.9.7 | **Doctor rule: `fork_bomb`** - fires CRITICAL when fork rate > 500/s per cgroup | P1 | |
| 10.9.8 | **Exit code enrichment:** map common exit codes to human explanations (137=OOMKill, 139=SIGSEGV, 143=SIGTERM) | P0 | |

### 10.10 - File Descriptor Deep Tracking *(upgrade from growth-rate only)*

> **Why:** Current FD tracking only measures open/close delta rate. It can't tell you WHAT is leaking (sockets vs files vs pipes) or WHICH specific connections are being leaked.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.10.1 | **Expand `fd_track.c`:** on open, capture the fd type via `f_mode` or by hooking `socket()` separately. Track: regular file, socket, pipe, eventfd, epoll, inotify | P0 | "FD leak is specifically socket FDs - connection pool not closing" |
| 10.10.2 | **Per-type FD accounting:** separate growth rate for socket FDs vs file FDs vs pipe FDs | P0 | |
| 10.10.3 | **Epoll/inotify exhaustion:** track epoll_create/inotify_init calls. Monitor `/proc/sys/fs/inotify/max_user_watches` | P1 | "inotify watches 98% exhausted - file watchers will fail" |
| 10.10.4 | **Doctor rule: `socket_fd_leak`** - fires when socket FD growth > threshold, with connection count | P0 | More actionable than generic "FD leak" |
| 10.10.5 | **Doctor rule: `inotify_exhaustion`** - fires when inotify watches approach limit | P1 | Common in Node.js file-watcher setups |

### 10.11 - Kubernetes-Native Context Enrichment *(make findings actionable)*

> **Why:** Every rule above fires with PIDs and cgroup IDs. On Kubernetes, nobody cares about PIDs - they care about pod names, namespaces, deployments, and services. Without this, Kerno is useless on K8s.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.11.1 | **Implement cgroup-to-pod resolver:** parse cgroup v2 path (`/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope`) → (pod UID, container ID) | P0 | Must handle containerd, CRI-O, Docker cgroup formats |
| 10.11.2 | **Pod metadata cache:** read pod info from kubelet read-only API (`localhost:10255/pods`) or downward API or K8s API with informer. Cache with TTL. | P0 | Maps (pod UID) → (name, namespace, labels, ownerRef, node) |
| 10.11.3 | **Enrichment layer:** every Finding and every event gets `.Pod`, `.Namespace`, `.Container`, `.Deployment`, `.Node` fields | P0 | |
| 10.11.4 | **Namespace-scoped doctor:** `kerno doctor --namespace payments` - only report findings for pods in that namespace | P0 | |
| 10.11.5 | **Pod-scoped doctor:** `kerno doctor --pod checkout-api-xyz` - diagnosis focused on one pod | P0 | |
| 10.11.6 | **Node-level summary:** group findings by node and show per-node health in cluster mode | P1 | |
| 10.11.7 | **Service name resolution:** map pod labels → K8s Service name via label selector matching | P1 | "payment-service (3 pods) experiencing TCP retransmit storm" |
| 10.11.8 | **Auto-detect K8s:** if running inside a pod or if `/var/run/secrets/kubernetes.io/serviceaccount/token` exists, enable K8s enrichment automatically | P0 | Zero config |

### 10.12 - Expanded Syscall Intelligence

> **Why:** Current syscall tracking sees latency and error rate but doesn't understand WHICH errors matter. `EAGAIN` on a non-blocking socket is normal. `ENOSPC` on write is an emergency.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.12.1 | **Error code classification:** expand `syscall_latency.c` to capture the actual errno (return value) not just "negative = error" | P0 | Distinguish EAGAIN (benign) from ENOSPC/ENOMEM/ECONNREFUSED (real failures) |
| 10.12.2 | **Syscall family grouping:** group syscalls into families (network: connect/accept/send/recv, filesystem: open/read/write/stat, memory: mmap/mprotect/brk) for higher-level diagnosis | P0 | "Network syscall error rate is 12%" is more useful than "connect() error rate is 12%" |
| 10.12.3 | **Doctor rule: `enospc_errors`** - fires CRITICAL on any ENOSPC returns | P0 | "write() returning ENOSPC - disk full" |
| 10.12.4 | **Doctor rule: `econnrefused_spike`** - fires when ECONNREFUSED rate spikes on connect() | P0 | "Backend service is refusing connections" |
| 10.12.5 | **Doctor rule: `enomem_errors`** - fires when mmap/brk return ENOMEM | P0 | "Memory allocation failing - process cannot allocate more memory" |

### 10.13 - Thermal & Hardware Degradation

> **Why:** Thermal throttling silently cuts CPU performance by 30-50%. On bare metal and VMs with passed-through hardware, this is a real production issue.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.13.1 | **CPU frequency monitor:** read `/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq` vs `cpuinfo_max_freq` | P1 | "CPU running at 60% of max frequency - thermal throttling" |
| 10.13.2 | **Thermal zone monitor:** read `/sys/class/thermal/thermal_zone*/temp` | P1 | "CPU temperature 92°C - approaching thermal shutdown at 100°C" |
| 10.13.3 | **Doctor rule: `cpu_throttled_thermal`** - fires when current freq < 80% of max | P1 | |
| 10.13.4 | **Doctor rule: `thermal_critical`** - fires WARNING at 85°C, CRITICAL at 95°C | P1 | |

### 10.14 - Node Pressure & Kubelet Eviction Detection *(K8s #3 pain point)*

> **Why:** When a node hits disk/memory/PID pressure thresholds, kubelet starts evicting pods - seemingly at random to the SRE. Kerno runs on the node and can see the exact pressure building before kubelet acts. Nobody else warns you BEFORE evictions start.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.14.1 | **Node memory pressure detector:** watch system-wide MemAvailable vs kubelet's `evictionHard.memory.available` threshold (default 100Mi). Read kubelet config from `/var/lib/kubelet/config.yaml` or `/configz` API | P0 | "Node memory available: 78Mi. Kubelet eviction threshold: 100Mi. Pod evictions imminent." |
| 10.14.2 | **Node disk pressure detector:** watch root filesystem + imagefs available vs kubelet `evictionHard.nodefs.available` (default 10%) and `evictionHard.imagefs.available` (default 15%) | P0 | "Root filesystem 93% full. Kubelet will start evicting pods at 90%." |
| 10.14.3 | **Node PID pressure detector:** read `/proc/sys/kernel/pid_max` vs current PID count from `/proc/loadavg` field 4. Also check kubelet `evictionHard.pid.available` | P0 | "Node has 31,892 of 32,768 PIDs in use. New pod scheduling will fail." |
| 10.14.4 | **Kubelet eviction timeline prediction:** combine memory/disk/PID growth rates with kubelet thresholds to predict WHEN eviction will trigger | P0 | "At current memory growth rate, kubelet will begin evictions in ~4 minutes" |
| 10.14.5 | **Doctor rule: `node_memory_pressure`** - fires WARNING when within 2x of kubelet threshold, CRITICAL when within 1x | P0 | |
| 10.14.6 | **Doctor rule: `node_disk_pressure`** - fires WARNING at kubelet soft threshold, CRITICAL at hard threshold | P0 | |
| 10.14.7 | **Doctor rule: `node_pid_pressure`** - fires WARNING at 80%, CRITICAL at 90% of pid_max | P0 | |
| 10.14.8 | **Ephemeral storage tracking per pod:** read `/var/lib/kubelet/pods/<uid>/volumes/` size to detect which pod is consuming ephemeral storage | P1 | "logging-sidecar in pod checkout-api is using 4.2GB ephemeral storage (limit: 5GB)" |

### 10.15 - Network Interface & Bandwidth Saturation *(the silent performance killer)*

> **Why:** A saturated network interface causes retransmits, drops, and latency - but the TCP monitor only sees the symptoms, not the cause. SREs need to know "eth0 is at 94% bandwidth" not just "TCP RTT is high."

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.15.1 | **NIC stats collector:** read `/sys/class/net/<iface>/statistics/` every 1s. Track rx_bytes, tx_bytes, rx_dropped, tx_dropped, rx_errors, tx_errors, collisions per interface | P0 | Foundation for all NIC diagnostics |
| 10.15.2 | **Bandwidth saturation detector:** compute bytes/sec vs link speed (`/sys/class/net/<iface>/speed`). Detect when utilization > 80% | P0 | "eth0 transmitting at 9.2 Gbps on 10G link (92% saturated)" |
| 10.15.3 | **NIC error/drop counter:** detect rising rx_errors, tx_errors, rx_dropped, tx_dropped | P0 | "eth0: 1,247 rx_dropped in last 30s - receive ring buffer may be too small" |
| 10.15.4 | **ARP/NDP table pressure:** read `/proc/net/arp` entry count vs `/proc/sys/net/ipv4/neigh/default/gc_thresh3` | P1 | "ARP table at 89% capacity (4,450/5,000). New neighbor resolution will fail." - common on large flat K8s networks |
| 10.15.5 | **Veth pair health:** for K8s pods, identify the veth pair and check both ends for errors/drops | P1 | "veth45abc (pod checkout-api) has 342 tx_dropped - pod network congested" |
| 10.15.6 | **MTU mismatch detector:** compare MTU across interfaces in the same network path. Hook `tracepoint/net/net_dev_xmit` and watch for ICMP "fragmentation needed" or track `ip_forward` drops | P2 | "PMTUD blackhole detected - packets > 1400 bytes are being silently dropped between pod-A and pod-B" |
| 10.15.7 | **Doctor rule: `nic_bandwidth_saturated`** - fires WARNING at 80%, CRITICAL at 95% of link speed | P0 | |
| 10.15.8 | **Doctor rule: `nic_errors`** - fires when error/drop rate > 0 sustained | P0 | "Network interface errors indicate hardware, driver, or configuration problem" |
| 10.15.9 | **Doctor rule: `arp_table_pressure`** - fires when ARP/NDP table > 75% | P1 | |
| 10.15.10 | **Doctor rule: `veth_drops`** - fires when pod veth pair shows drops | P1 | |

### 10.16 - CPU Steal Time & VM Neighbor Noise *(cloud K8s reality)*

> **Why:** On AWS/GCP/Azure, your node shares physical hardware with other tenants. CPU steal time means another VM is eating your CPU cycles. This is invisible to `top` unless you know where to look, and it causes mysterious "everything is slow" incidents.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.16.1 | **CPU steal time collector:** read `/proc/stat` and compute steal% per CPU. Also read iowait%, softirq%, system% for full CPU accounting | P0 | "CPU 3: 23% steal - the cloud hypervisor is taking your CPU time" |
| 10.16.2 | **CPU pressure stall detector:** read `/proc/pressure/cpu` (PSI) for system-wide CPU pressure (some, full) | P0 | "CPU full pressure: 34% - tasks are stalled waiting for CPU 34% of the time" |
| 10.16.3 | **Doctor rule: `cpu_steal_high`** - fires WARNING at >5% steal, CRITICAL at >15% | P0 | "CPU steal time is 18%. Your cloud instance is being throttled by the hypervisor. Consider a dedicated host or larger instance." |
| 10.16.4 | **Doctor rule: `cpu_iowait_high`** - fires when iowait% > 20% sustained | P0 | "CPUs spending 34% of time waiting for I/O - disk is the bottleneck, not CPU" |
| 10.16.5 | **Doctor rule: `cpu_pressure_stall`** - fires when PSI full > 10% | P0 | |

### 10.17 - Container Runtime & Overlay Filesystem Health

> **Why:** Containerd/CRI-O stalls cause pod startup failures, image pull timeouts, and exec hangs. Overlay filesystem saturation causes writes to become absurdly slow. These are pure K8s issues that no APM tool can see.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.17.1 | **Container runtime health:** check containerd/CRI-O socket responsiveness. Poll `ctr version` (containerd) or `crictl info` (CRI-O) with timeout. Track response latency | P0 | "containerd API response time: 4.2s (normally <50ms). Container operations are stalled." |
| 10.17.2 | **Overlay filesystem latency:** measure write latency to `/var/lib/containerd/` or `/var/lib/docker/overlay2/`. Use existing disk_io eBPF data filtered to overlay mount device | P1 | "Overlay filesystem write P99: 890ms. Container layer I/O is severely degraded." |
| 10.17.3 | **Image pull tracking:** watch for `registry` connect syscalls + DNS resolution to registry endpoints. Detect slow/failing pulls from kernel signals | P1 | "Image pulls taking >60s - registry DNS resolution timing out" |
| 10.17.4 | **Doctor rule: `container_runtime_stall`** - fires when runtime API > 2s response | P0 | |
| 10.17.5 | **Doctor rule: `overlay_fs_slow`** - fires when overlay device write latency > thresholds | P1 | |

### 10.18 - Time Synchronization & Clock Drift

> **Why:** Clock drift breaks TLS certificate validation, causes Kerberos auth failures, corrupts distributed database consistency, and makes log correlation impossible. On K8s, it causes pod-to-pod auth failures and Istio mTLS breakage.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.18.1 | **Clock offset detector:** read `/sys/devices/system/clocksource/clocksource0/current_clocksource` and call `clock_gettime(CLOCK_REALTIME)` vs `CLOCK_MONOTONIC` delta. Also check `adjtimex()` for NTP status | P0 | "System clock offset: +3.2 seconds from NTP. TLS and auth may fail." |
| 10.18.2 | **NTP sync status:** parse `timedatectl status` or read chrony/ntpd socket for sync state and offset | P0 | "NTP not synchronized. Last sync: 47 minutes ago." |
| 10.18.3 | **Doctor rule: `clock_drift`** - fires WARNING at >100ms drift, CRITICAL at >1s | P0 | "Clock drift of 1.3s detected. Impact: TLS handshakes may fail, distributed databases may reject writes, log timestamps are unreliable." |
| 10.18.4 | **Doctor rule: `ntp_unsynchronized`** - fires WARNING when NTP sync lost for > 5 minutes | P0 | |

### 10.19 - Service Mesh & L7 Proxy Health *(Istio/Envoy/Linkerd)*

> **Why:** Most production K8s runs a service mesh. When Envoy/Linkerd sidecar gets slow or breaks, EVERY service call in the namespace fails. Kerno can detect the kernel-level signals of a sick sidecar.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.19.1 | **Sidecar resource detection:** identify envoy/linkerd-proxy containers by cgroup path or process name. Track their CPU, memory, FD, and syscall latency separately | P0 | "envoy-proxy in payment-api using 1.8GB RSS (limit: 2GB) - sidecar approaching OOM" |
| 10.19.2 | **Proxy connection pool exhaustion:** track envoy's FD count and connect() syscall patterns. Detect when sidecar is running out of connections | P0 | "envoy has 14,200 open FDs (soft limit: 15,000). Upstream connection pool likely exhausted." |
| 10.19.3 | **Proxy-induced latency detector:** compare syscall latency for traffic going through the sidecar vs direct. Track additional latency from sidecar `accept()` → `connect()` → `sendmsg()` chain | P1 | "Service mesh sidecar adding 12ms P99 overhead (normally <1ms)" |
| 10.19.4 | **Doctor rule: `sidecar_resource_pressure`** - fires when envoy/linkerd-proxy resource usage is high relative to limits | P0 | |
| 10.19.5 | **Doctor rule: `sidecar_connection_pool`** - fires when proxy FD count approaching limit | P0 | |
| 10.19.6 | **Doctor rule: `sidecar_latency_overhead`** �� fires when mesh overhead exceeds 5ms P99 | P1 | |

### 10.20 - IPVS/Kube-proxy & K8s Service Networking

> **Why:** kube-proxy (iptables or IPVS mode) is the invisible glue of K8s networking. When it breaks, Services stop working but pod-to-pod works fine - the most confusing failure mode in K8s.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.20.1 | **IPVS connection table monitor:** read `/proc/net/ip_vs_conn` for connection count, state distribution, active/inactive ratio | P0 | "IPVS has 45,000 active connections to service backend - possible connection leak" |
| 10.20.2 | **IPVS real server health:** read `/proc/net/ip_vs` for per-backend connection count and weight. Detect imbalanced backends | P0 | "IPVS backend 10.0.3.5:8080 receiving 0 connections while 10.0.3.6:8080 has 12,000 - backend is down but not removed" |
| 10.20.3 | **Iptables rule count monitor:** read `iptables-save | wc -l` (or nftables equivalent). On large clusters, iptables mode creates thousands of rules causing CPU burn | P1 | "12,847 iptables rules detected. kube-proxy in iptables mode on large cluster causes high CPU. Consider IPVS mode." |
| 10.20.4 | **Service ClusterIP connectivity:** detect when conntrack entries for ClusterIP traffic show high failure rate (SYN without ESTABLISHED) | P0 | "ClusterIP service 10.96.0.10 (kube-dns): 34% of connections failing - endpoint may be unhealthy" |
| 10.20.5 | **Doctor rule: `ipvs_backend_down`** - fires when a backend has zero connections while others are active | P0 | |
| 10.20.6 | **Doctor rule: `ipvs_connection_leak`** - fires when IPVS connections grow unbounded | P1 | |
| 10.20.7 | **Doctor rule: `kube_proxy_overhead`** - fires when iptables rule count > 5000 | P1 | |
| 10.20.8 | **Doctor rule: `service_connectivity_failure`** - fires when ClusterIP connection failure rate > threshold | P0 | |

### 10.21 - Cgroup memory.high Throttling (distinct from OOMKill)

> **Why:** Kubernetes 1.22+ supports `memory.high` via MemoryQoS. When a container exceeds `memory.high`, the kernel throttles its memory allocations (reclaim stalls) instead of killing it. This causes mysterious slowdowns that look like "the app is slow but nothing is wrong." Phase 10.1 only checks `memory.max` (the kill boundary) - this catches the throttle boundary.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 10.21.1 | **Memory.high throttle detector:** read `memory.events` counter `high` (increments on each reclaim event). Read `memory.high` vs `memory.current` | P0 | "payment-api memory reclaim events: 4,200 in last 30s. Memory.high=512Mi, current=498Mi. Kernel is throttling allocations." |
| 10.21.2 | **Memory reclaim latency:** attach to `tracepoint/vmscan/mm_vmscan_direct_reclaim_begin` + `end`. Track per-cgroup reclaim stall time | P0 | Direct measure of "how long does the kernel stall this container to reclaim memory?" |
| 10.21.3 | **Doctor rule: `memory_high_throttle`** - fires when memory.events.high increments > 100/s | P0 | "Container is being memory-throttled by the kernel (memory.high). Allocations are stalling. Increase memory request or optimize usage." |

### Definition of Done - Phase 10

**Core detection:**
- [ ] `kerno doctor` on a K8s node with CPU-throttled pods reports cgroup throttling with pod names
- [ ] `kerno doctor` detects DNS failures when CoreDNS is degraded
- [ ] `kerno doctor` reports connection refused/reset, not just retransmits
- [ ] `kerno doctor` detects memory leaks at both system and per-process level
- [ ] `kerno doctor` detects lock contention causing "slow app, low CPU"
- [ ] `kerno doctor` warns about conntrack/ephemeral port/inode exhaustion
- [ ] `kerno doctor` catches kernel warnings and soft lockups before a crash
- [ ] `kerno doctor` detects crash loops from kernel-level exit signals

**K8s-native:**
- [ ] `kerno doctor --namespace payments` shows only findings for that namespace
- [ ] Every finding includes pod name, namespace, container when running on K8s
- [ ] Node pressure detection warns BEFORE kubelet starts evicting pods
- [ ] Service mesh sidecar (envoy/linkerd) resource pressure detected
- [ ] IPVS/kube-proxy service connectivity failures detected
- [ ] Cgroup memory.high throttling detected (distinct from OOMKill)
- [ ] Container runtime (containerd/CRI-O) stalls detected

**Network completeness:**
- [ ] IPv6 TCP monitoring works
- [ ] NIC bandwidth saturation and error counters monitored
- [ ] ARP table pressure on large flat networks detected
- [ ] Veth pair drops for pod networking detected

**System health:**
- [ ] CPU steal time (cloud VM neighbor noise) detected
- [ ] Clock drift / NTP sync loss detected
- [ ] At least 60 doctor rules total (up from 11)
- [ ] All new eBPF programs gracefully skip on unsupported kernels
- [ ] Zero false positives on a healthy idle system

**The acid test:** Run `kerno doctor` on a production K8s node experiencing ANY of these real incidents, and it MUST detect and explain it:
1. Pod CPU throttled by cgroup limits
2. CoreDNS intermittent failure
3. Backend service connection refused
4. Container OOMKilled
5. CrashLoopBackOff from segfault
6. Node disk pressure → pod eviction
7. Conntrack table full → service failures
8. Clock drift → TLS failures
9. CPU steal → everything slow
10. Memory.high throttle → allocation stalls

---

### New Doctor Rules Summary (Phase 10)

| # | Rule | Signal Source | Severity | K8s Impact |
|---|------|-------------|----------|-----------|
| 12 | `cpu_throttled` | cgroup v2 cpu.stat | CRIT | Pod CPU limit too low |
| 13 | `memory_limit_pressure` | cgroup v2 memory.current/max | WARN/CRIT | Pod OOMKill prediction |
| 14 | `io_throttled` | cgroup v2 io.pressure | WARN | Pod I/O limit hit |
| 15 | `pid_exhaustion` | cgroup v2 pids.current/max | WARN | Fork/thread exhaustion |
| 16 | `dns_resolution_slow` | dns_monitor eBPF | WARN/CRIT | CoreDNS degraded |
| 17 | `dns_failure_rate` | dns_monitor eBPF | WARN/CRIT | DNS SERVFAIL spike |
| 18 | `dns_timeout` | dns_monitor eBPF | CRIT | Cascading timeout |
| 19 | `tcp_connection_failures` | tcp_monitor expanded | WARN/CRIT | Backend down |
| 20 | `tcp_drops` | tcp_drop tracepoint | WARN/CRIT | Kernel dropping packets |
| 21 | `tcp_backlog_overflow` | /proc/net/netstat | WARN | Service overloaded |
| 22 | `swap_thrashing` | /proc/vmstat | WARN/CRIT | System memory exhausted |
| 23 | `page_fault_storm` | page_fault eBPF | WARN | Thrashing |
| 24 | `memory_leak_detected` | /proc/<pid>/statm | WARN | Per-process leak |
| 25 | `lock_contention_high` | lock_contention eBPF | WARN/CRIT | App stalled on locks |
| 26 | `futex_storm` | futex eBPF | WARN | Thundering herd |
| 27 | `socket_buffer_overflow` | sock tracepoint | WARN | Data loss |
| 28 | `ephemeral_port_exhaustion` | /proc/net/tcp | WARN/CRIT | Connection failure |
| 29 | `conntrack_exhaustion` | /proc/sys/net/nf_conntrack | WARN/CRIT | K8s service failure |
| 30 | `kernel_warning` | printk tracepoint | WARN/CRIT | System instability |
| 31 | `hung_task` | printk tracepoint | CRIT | Process stuck |
| 32 | `irq_storm` | softirq tracepoint | WARN | Network interrupt flood |
| 33 | `inode_exhaustion` | /proc/sys/fs/inode-nr | WARN/CRIT | File creation fails |
| 34 | `writeback_pressure` | /proc/vmstat | WARN | fsync blocking |
| 35 | `disk_space_critical` | statfs | WARN/CRIT | Pod eviction risk |
| 36 | `disk_queue_saturated` | /sys/block/*/stat | WARN | Device bottleneck |
| 37 | `nfs_hang` | NFS tracepoint | WARN/CRIT | Filesystem unresponsive |
| 38 | `crash_loop` | process_lifecycle eBPF | CRIT | CrashLoopBackOff |
| 39 | `signal_storm` | process_lifecycle eBPF | CRIT | Segfaults/crashes |
| 40 | `fork_bomb` | process_lifecycle eBPF | CRIT | Resource exhaustion |
| 41 | `socket_fd_leak` | fd_track expanded | WARN | Connection leak |
| 42 | `inotify_exhaustion` | /proc/sys/fs/inotify | WARN | File watchers fail |
| 43 | `enospc_errors` | syscall_latency expanded | CRIT | Disk full |
| 44 | `econnrefused_spike` | syscall_latency expanded | WARN/CRIT | Backend down |
| 45 | `enomem_errors` | syscall_latency expanded | CRIT | Memory allocation fail |
| 46 | `cpu_throttled_thermal` | sysfs thermal | WARN | Silent perf loss |
| 47 | `thermal_critical` | sysfs thermal | WARN/CRIT | Hardware at risk |
| 48 | `node_memory_pressure` | /proc/meminfo + kubelet config | WARN/CRIT | Pod eviction imminent |
| 49 | `node_disk_pressure` | statfs + kubelet config | WARN/CRIT | Pod eviction imminent |
| 50 | `node_pid_pressure` | /proc/loadavg + pid_max | WARN/CRIT | Fork/exec fails |
| 51 | `nic_bandwidth_saturated` | /sys/class/net/*/statistics | WARN/CRIT | Network bottleneck |
| 52 | `nic_errors` | /sys/class/net/*/statistics | WARN/CRIT | Hardware/driver issue |
| 53 | `arp_table_pressure` | /proc/net/arp + gc_thresh3 | WARN | Neighbor resolution fails |
| 54 | `veth_drops` | /sys/class/net/veth*/statistics | WARN | Pod network congested |
| 55 | `cpu_steal_high` | /proc/stat | WARN/CRIT | Cloud VM throttled |
| 56 | `cpu_iowait_high` | /proc/stat | WARN | Disk is the real bottleneck |
| 57 | `cpu_pressure_stall` | /proc/pressure/cpu | WARN/CRIT | Tasks stalled for CPU |
| 58 | `container_runtime_stall` | containerd/CRI-O socket | WARN/CRIT | Pod operations hanging |
| 59 | `overlay_fs_slow` | disk_io eBPF filtered | WARN | Container layer I/O slow |
| 60 | `clock_drift` | adjtimex/timedatectl | WARN/CRIT | TLS/auth/DB failures |
| 61 | `ntp_unsynchronized` | chrony/ntpd status | WARN | Time source lost |
| 62 | `sidecar_resource_pressure` | cgroup stats for envoy/linkerd | WARN/CRIT | Mesh degraded |
| 63 | `sidecar_connection_pool` | FD count for proxy process | WARN/CRIT | Upstream exhausted |
| 64 | `sidecar_latency_overhead` | syscall latency comparison | WARN | Mesh adding latency |
| 65 | `ipvs_backend_down` | /proc/net/ip_vs | CRIT | Backend not receiving traffic |
| 66 | `ipvs_connection_leak` | /proc/net/ip_vs_conn | WARN | Unbounded connections |
| 67 | `kube_proxy_overhead` | iptables rule count | WARN | High CPU from rules |
| 68 | `service_connectivity_failure` | conntrack + ClusterIP | WARN/CRIT | K8s Service broken |
| 69 | `memory_high_throttle` | cgroup memory.events.high | WARN/CRIT | Silent allocation stalls |

---

## Phase 11 - SLO Bridge *(Month 4–5)*

> **Goal:** `KernelSLO` CRD → error budget tracking → Prometheus metrics.

### 11.1 Implementation

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 11.1.1 | Define `KernelSLO` CRD schema (as in idea.md §9) | P1 | |
| 11.1.2 | CRD controller: watch KernelSLO resources, evaluate signals against thresholds | P1 | |
| 11.1.3 | Error budget computation: `budget_remaining = 1.0 - (violations / total_window)` | P1 | |
| 11.1.4 | Burn rate: 1h, 6h, 24h, 3d windows | P1 | |
| 11.1.5 | Prometheus metrics: `kerno_slo_budget_remaining`, `kerno_slo_burn_rate` | P1 | |
| 11.1.6 | SLO state surfaced via the Incident CRD (Phase 18.2) and Prometheus metrics - no kerno-side UI; visualization via Grafana | P1 | |
| 11.1.7 | OpenSLO spec compatibility | P2 | |
| 11.1.8 | Sloth/Pyrra integration | P2 | |

---

## Phase 12 - KEDA Scaler & Advanced K8s *(Month 5–6)*

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 12.1 | KEDA external scaler gRPC server | P2 | |
| 12.2 | NetworkPolicy visibility (dropped connection detection) | P2 | |
| 12.3 | `kerno doctor --pod`, `--namespace`, `--node`, `--cluster` modes | P1 | |

---

## Phase 13 - CNCF Readiness *(Month 6–7)*

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 13.1 | OpenSSF Best Practices Badge - complete questionnaire | P1 | |
| 13.2 | 3+ contributors from different organizations | P1 | |
| 13.3 | Regular release cadence (at least every 3 months) | P1 | |
| 13.4 | KubeCon talk proposal submission | P2 | |
| 13.5 | CNCF Sandbox application at `github.com/cncf/sandbox` | P2 | |
| 13.6 | Documentation site (docs.lowplane.dev/kerno) | P2 | |

---

## Phase 14 - Causal Timeline & Incident Context *(Month 5–6)*

> **Goal:** Make every `kerno doctor` finding tell a *story*. Not "disk is slow," but "at 10:01 disk crossed → 10:02 DB fsync delay → 10:03 payment p99 spiked → 10:04 checkout errors. Root cause: disk." This is the genuinely new thing nobody else does - Datadog shows symptoms, Cilium shows traffic, Kerno shows the **cause-and-effect chain**.

**Why this is the headline (and topology is not):** Cilium / Hubble / Linkerd already do eBPF service maps. Building a competing topology UI puts us in someone else's lane. The unique angle is *temporal correlation across kernel signals* - turning "the system is sad" into a chronological narrative with a root cause. That's the screenshot that goes on Hacker News.

**UX north star - "one command, anywhere, gets the answer":**

| Environment | Command |
|-------------|---------|
| Linux VM    | `sudo kerno doctor` |
| Kubernetes  | `kubectl kerno doctor` |

One command. The agent runs where the kernel is; the user runs where their terminal already is.

### 14.1 Signal History Store *(foundation)*

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 14.1.1 | Per-signal time-series ring buffer: last 10 minutes of every signal kept in memory at 1Hz resolution | P0 | New `internal/collector/history.go` |
| 14.1.2 | Threshold-crossing tracker: record exact timestamp the first time each signal exceeds its warning / critical threshold | P0 | Becomes the timeline anchor |
| 14.1.3 | Bounded memory: cap history at 600 samples × 6 signals × 200 dimensions = ~2 MB | P0 | Reuse `LabelCardinalityLimit` pattern |

### 14.2 Causal Timeline Engine *(the headline feature)*

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 14.2.1 | Timeline reconstructor: for each finding, walk backwards through the signal history and order all threshold crossings within the last N minutes | P0 | New `internal/doctor/timeline.go` |
| 14.2.2 | Causal scoring: rank ordered events by (a) temporal precedence, (b) known signal-to-signal dependency edges (disk → fsync → DB → upstream), (c) topology hop count | P0 | Curated dependency graph in code, not learned |
| 14.2.3 | Doctor renderer: each finding shows a "How this unfolded" block with a 5-line ordered timeline | P0 | This is the demo screenshot |
| 14.2.4 | JSON renderer: emit `timeline: [{ts, signal, value, threshold}]` for each finding | P0 | For automation / Slack bots |
| 14.2.5 | Confidence label per timeline: `high` if every step has a known dependency edge, `inferred` otherwise | P1 | Honesty over confidence theater |

**Reference output (the demo screenshot):**

```
❌ CRITICAL  Checkout latency spike

  Root cause: Disk I/O bottleneck on worker-03

  How this unfolded:
    10:01:14  Disk fsync p99 crossed 200ms (was 35ms)         ← root
    10:02:03  Postgres write latency p99 reached 410ms
    10:02:51  payment-api request p99 spiked to 1.2s
    10:03:22  checkout-api error rate hit 4.7% (SLO: <1%)     ← user-visible

  Impact:
    8 services degraded · ~1,200 user-facing errors in 90s

  Fix:
    iostat -x 1 5
    Check storage saturation on worker-03; consider write batching
```

### 14.3 "What Changed?" Detector *(second viral feature)*

> **Why:** During an incident, the first SRE question is always *"what changed?"* Today they ask in Slack and dig through git. Kerno can answer it in one command.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 14.3.1 | Track the last 15 minutes of: deployment generation bumps, ConfigMap revisions, Secret revisions, image SHA changes per pod | P0 | Polled every 30s via existing K8s adapter index - no new client-go |
| 14.3.2 | On `kerno doctor`, surface a "What Changed" section listing changes inside the incident window | P0 | |
| 14.3.3 | Score change relevance: changes to a pod that appears in the causal timeline are flagged as `likely related` | P0 | |
| 14.3.4 | Bare-metal fallback: track systemd unit restart counts, package upgrade timestamps from `/var/log/dpkg.log` / `/var/log/yum.log` | P1 | Works without K8s |

**Reference output:**

```
WHAT CHANGED  (last 15 min)
  10:00:42  payment-api  rolled out  (image: v2.3.1 → v2.3.2)   ← likely related
  09:58:11  ingress-nginx  ConfigMap revision 47 → 48
```

### 14.4 `kerno doctor --watch` Mode

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 14.4.1 | Re-evaluate signals every N seconds (default 10s); only re-render when state changes (new finding, severity change, finding cleared) | P0 | Lets SREs leave a terminal open during an incident |
| 14.4.2 | "Early signal" mode: also fire when a signal is within X% of its threshold and trending upward over the last M samples | P0 | The "trend warning" - not ML, just slope detection |
| 14.4.3 | Exit codes: 0 if clean, 1 if warnings, 2 if criticals - for shell loops and CI | P0 | |

**Reference output for early-signal mode:**

```
⚠ EARLY SIGNAL  (10:04:18)

  Disk fsync p99: 178ms → threshold 200ms  (rising, +12ms/sample)
  Likely to breach in next 60-90 seconds.
```

### 14.5 Minimal Topology Context *(supporting plumbing - not a hero command)*

> **Scope discipline:** Cilium / Hubble own service maps. We build the L4 flow tracker because the causal timeline needs it (knowing payment → database lets us walk the dependency chain). We expose a *minimal* `kerno topology --pod` for context, but it is **not** the pitch and we do not build the fancy UI, the `--unexpected` security tool, the DOT export, or the dashboard graph. If we ever feel tempted to add those, re-read principle #7.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 14.5.1 | L4 flow tracker: aggregate `tcp_monitor` events into `(src_pod, dst_pod, dst_port, proto)` edges with conn count + RTT | P0 | Reuses existing `internal/bpf/tcp_monitor.c` - no new BPF program |
| 14.5.2 | In-memory edge store with TTL decay (5 min) and per-namespace edge cap | P0 | Bounded; reuse `LabelCardinalityLimit` pattern |
| 14.5.3 | K8s metadata join: edges enriched with pod / service / namespace via existing `internal/adapter/kubernetes.go` | P0 | |
| 14.5.4 | `kerno topology --pod <name>` minimal CLI: tree output of callers + callees with health annotation. **No** `--unexpected`, **no** DOT export, **no** standalone topology positioning. | P1 | Demoted from P0 - supporting context only |
| 14.5.5 | Topology data feeds the causal timeline engine (14.2.2) and the impact-mapping section of doctor output | P0 | The real reason it exists |

### 14.6 `kubectl kerno` Plugin *(primary K8s UX)*

> **Why:** SREs live in `kubectl`. `kubectl exec -it kerno-xyz -- kerno doctor` is friction. The plugin makes Kerno feel native - one command, one cluster report, no node-picking.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 14.6.1 | `cmd/kubectl-kerno/main.go`: standalone binary discoverable as `kubectl kerno` | P0 | Single Go binary |
| 14.6.2 | Subcommand passthrough: `kubectl kerno doctor`, `kubectl kerno doctor --watch`, `kubectl kerno topology --pod <name>` | P0 | Same flags, same output, same exit codes |
| 14.6.3 | Node fan-out: list DaemonSet pods via Kubernetes API, exec the requested command on each in parallel, stream results back | P0 | Use `$KUBECONFIG`; no extra auth |
| 14.6.4 | Cluster-level aggregation: merge per-node `Signals` snapshots into one cluster snapshot before running doctor rules | P0 | New `internal/doctor/cluster.go` |
| 14.6.5 | `--node`, `--pod`, `--namespace` filters pushed to agents server-side | P0 | Avoid shipping irrelevant data |
| 14.6.6 | Helpful errors: if no kerno DaemonSet found, print the Helm install one-liner | P0 | |
| 14.6.7 | Krew manifest + submission to the official index | **P2 (deferred)** | Do this *after* we have users, not before. Krew is a marketing channel that only matters if the binary already works. |

### 14.7 Detection Rules That Use Topology + Timeline

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 14.7.1 | Cross-namespace cascade detector: fires when a degraded pod in ns A has callers in ns B with rising RTT/errors | P1 | New rule in `internal/doctor/rules` |
| 14.7.2 | NetworkPolicy drop visibility: hook `tcp_drop` / `kfree_skb_reason` tracepoint, attribute drops to pod pairs | P2 | Gated on kernel ≥ 5.17; not MVP |
| 14.7.3 | Pod / namespace / node scoping flags on `doctor`: `--pod`, `--namespace`, `--node` | P0 | |

### Definition of Done - Phase 14

- [ ] `kerno doctor` shows a causal timeline under every CRITICAL finding, with at least 3 ordered steps and the root signal labelled
- [ ] `kerno doctor --watch` re-renders only on state change and prints early-signal warnings before threshold breach in a synthetic test
- [ ] "What Changed" section surfaces a synthetic deployment rollout that occurred 90 seconds before an induced incident
- [ ] `kubectl kerno doctor` aggregates findings from every node into one cluster report
- [ ] `kerno topology --pod <name>` prints a minimal callers/callees tree with health annotations (no fancy framing, no `--unexpected`)
- [ ] Signal history memory bounded to <5 MB on a busy node

---

## Phase 15 - Incident Pattern Database *(Month 6–7)*

> **Goal:** Every confirmed root cause becomes a reusable pattern. Kerno gets smarter with each incident - without any LLM in the loop.

**Why this matters:** Pure deterministic learning. No AI required, no trust questions, just a growing library of correlated signal patterns. This is Layer 4 of the incident-remediation strategy and it stands on its own as a feature even if Phase 16 never ships.

### 15.1 Pattern Storage

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 15.1 | Pattern schema: `{trigger_signals[], timeline[], root_cause, blast_radius, fix_steps[], confidence, applied_count, success_count}` | P0 | |
| 15.2 | Embedded store: BoltDB at `/var/lib/kerno/patterns.db` - single binary, no external DB | P0 | Avoids dependency creep |
| 15.3 | `kerno incident record` CLI: capture the current `Signals` snapshot + a human-confirmed root cause as a pattern | P0 | Manual entry first; automated capture in Phase 16 |

### 15.2 Matching & Confidence

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 15.4 | Pattern matcher: doctor evaluates current signals against stored patterns, returns top-K with similarity score | P0 | Cosine over normalized signal vectors |
| 15.5 | Confidence math: `+1` on confirmed success, exponential decay on failed application, floor at 0.0 | P0 | |
| 15.6 | `kerno patterns list / show / export / import` for inspection + sharing across clusters | P1 | YAML import/export |
| 15.7 | Doctor renderer integration: matched patterns appear under each finding as "Seen before" with link to playbook | P0 | |
| 15.8 | Community pattern bundle: ship 10 curated patterns (FD leak → downstream timeout, OOM → cgroup throttle, etc.) | P1 | Default content for first run |

### Definition of Done - Phase 15

- [ ] `kerno incident record` round-trips through the store
- [ ] Synthetic incident matches a stored pattern with similarity ≥ 0.8
- [ ] Confidence decays correctly when a pattern is applied to a non-matching incident

---

## Phase 16 - Three-Tier Remediation Engine *(DEFERRED - TRUST GATE)*

> **Goal:** Document the remediation model so it's ready when trust is earned.
> **DO NOT START IMPLEMENTATION** until Kerno has been deployed in **≥10 production clusters for ≥6 months** without a Kerno-caused incident.

**Trust gate first.** Explicit user constraint: *"let keep ai automation for future. for now noone will trust us if we make it also."* This phase ships only after the deterministic doctor + topology + pattern database have built the credibility to justify automated action. Until then, this section exists as a design contract - anyone proposing remediation features earlier should be pointed here and asked: *has the trust gate been met?*

### 16.1 Tier Decision Table

| Tier | Confidence | Blast Radius | Examples |
|------|-----------|--------------|----------|
| **1 - Fully automated** | > 0.85 | low | fd_leak single replica → graceful pod restart · HPA below max → scale +2 · liveness failing → force restart · runqueue high → reschedule pod |
| **2 - Recommend, human confirms** | > 0.70 | medium / high | node-level issue → cordon + drain · stateful pod anomaly → failover · deployment regression → rollback · DB pool exhaustion → restart pooler · cross-ns cascade → isolate ns |
| **3 - Observe + alert only** | < 0.70 OR unknown OR critical | any | novel anomaly → alert + full eBPF trace dump · multi-cluster cascade → topology map · data corruption signal → alert + freeze automation |

### 16.2 The Feedback Loop (most important - never skip)

```
Action taken
   → monitor signals for N minutes post-action
   → did the anomaly resolve?
        YES → record success, boost pattern confidence
        NO  → record failure, decay pattern confidence,
              escalate to human, NEVER retry the same action automatically
```

This is how Kerno gets smarter over time. Without this loop, the AI layer is static and degrades in trust. Every action must close the loop.

### 16.3 Implementation Tasks (when greenlit)

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 16.3.1 | Action interface: `Plan() → DryRun() → Execute() → Verify()` with hard timeouts | P0 | Verify step is the feedback loop |
| 16.3.2 | Tier classifier: confidence + blast_radius → tier; default to Tier 3 on any uncertainty | P0 | Fail-closed |
| 16.3.3 | Built-in actions: pod restart, HPA scale, cordon/drain, deployment rollback (each as a separate file under `internal/remediation/actions/`) | P0 | Uses Kubelet / API server with explicit RBAC, no client-go magic |
| 16.3.4 | Dual-control: every Tier 2 action requires a second human approver (Slack / web UI button) | P0 | |
| 16.3.5 | Audit log: append-only JSON of every decision, action, outcome - never deleted | P0 | Forensic requirement |
| 16.3.6 | Kill switch: single env var or config field that drops everything to Tier 3 globally | P0 | |
| 16.3.7 | Per-namespace opt-in: Tier 1/2 actions only on namespaces with `kerno.io/auto-remediation: enabled` annotation | P0 | Default off |
| 16.3.8 | Post-action signal monitor: watch the affected scope for N minutes, classify resolved / unchanged / worsened | P0 | Drives the feedback loop |
| 16.3.9 | Confidence updates feed back into Phase 15 pattern store | P0 | |

### Definition of Done - Phase 16

- [ ] All actions ship with a working `--dry-run`
- [ ] Kill switch verified in chaos test
- [ ] Default install runs at Tier 3 only
- [ ] At least 50 successful Tier 1 actions in production before enabling Tier 2 anywhere

---

## Phase 17 - LLM Communication Layer *(Bounded Scope)*

> **Goal:** Use LLMs only for two human-facing jobs. Not detection, not correlation, not decisions.

**Strict scope.** Detection and root-cause analysis stay in the deterministic engine (Phase 3 + 14 + 15). LLMs are only allowed to translate structured RCA output into human-readable text. This keeps the trust model intact and the AI failure modes bounded.

### 17.1 Allowed Jobs

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 17.1 | **Job 1 - Incident summary:** input is structured RCA from Phase 14/15, output is a paragraph in plain English with timeline, blame, current state, suggested fix | P1 | Reuses `internal/ai` providers |
| 17.2 | **Job 2 - Runbook generation:** input is a confirmed pattern from Phase 15, output is a markdown runbook auto-committed to a configurable Git repo (e.g., `runbooks/`) | P2 | |
| 17.3 | Prompt cache + TTL: identical incidents return cached summaries to control cost | P1 | Mirrors existing AI cache from Phase 5 |
| 17.4 | Privacy modes already in `internal/ai`: `full` / `redacted` / `summary` apply unchanged | P0 | |
| 17.5 | **Explicit non-goals (documented in code comments):** LLMs MUST NOT do anomaly detection, root cause inference, or automated decisions. Any future contributor proposing this gets pointed at this row. | P0 | |
| 17.6 | Fallback: on LLM failure, output the raw structured RCA - never hide an incident behind an LLM error | P0 | |

### 17.2 Example Output (Job 1)

> *payments-api has been leaking file descriptors since 14:32 UTC. This caused I/O pressure on worker-03 which degraded checkout-api response times by 340%. Kerno restarted payments-api at 14:41 UTC. Response times are recovering. Root cause: connection pool not releasing sockets on timeout. Suggested fix: set `tcp_keepalive` in payments-api config.*

### Definition of Done - Phase 17

- [ ] Incident summary generated for a synthetic OOM cascade reads naturally to a non-kernel engineer
- [ ] Runbook auto-commit creates a PR in a test repo
- [ ] Disabling AI completely still produces full deterministic incident output

---

## Phase 18 - Viral K8s Distribution *(runs parallel to Phases 14–15)*

> **Goal:** Make every diagnosis leave a trail. Shared links, CRDs, PR comments, Slack messages - each is a brand touch. Features in Phases 14–15 win *trust*; Phase 18 wins *distribution*. Both are required; neither is sufficient alone.

**The core insight:** Kerno doesn't need a marketing team. It needs the *product itself* to be a distribution engine. Every engineer who runs `kerno doctor` should leave behind a kerno-branded artifact - a URL, a CRD, a PR comment, a Slack message - that reaches 5–10 more engineers.

**Explicit non-goals (per principles #7 and the AI trust gate):**
- ❌ No Kerno-authored UI dashboards, period - Hubble/Cilium own topology UI; Grafana (via the existing Prometheus exporter) handles time-series; the Incident CRD (18.2) makes us appear in k9s/Lens/Headlamp/Backstage automatically. We do not write or maintain frontend code.
- ❌ No Kerno-authored Backstage / ArgoCD / Lens plugins. The Incident CRD (18.2) makes kerno appear in those UIs automatically without us maintaining N adapters.
- ❌ No auto-remediation hooks inside sinks - notification only. Phase 16 trust gate applies.
- ❌ No IDE extensions (VS Code / JetBrains) until ≥5k GitHub stars. Deep invest, thin viral return early on.

### 18.1 Shareable Incident Links - *the asciinema model for incidents*

> `kerno doctor --share` uploads a redacted incident report to `kerno.sh/i/abc123` and prints the URL. Every Slack paste is free marketing. **Highest viral leverage per day of engineering.**

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 18.1.1 | `kerno doctor --share` flag: serialize findings + causal timeline + "What Changed" context to a `kerno.IncidentReport` JSON schema | P0 | Reuses Phase 14 output; no new data collection |
| 18.1.2 | Redaction pass before upload: strip pod IPs, env vars, container args, node hostnames (replace with `node-01`, `pod-a1b2c3`, etc). Opt-out with `--share --raw` | P0 | Privacy-first or engineers won't hit the button |
| 18.1.3 | Upload service: Go binary at `share.kerno.sh` backed by BoltDB + S3-compatible blob store. Single binary, Cloudflare in front for rate-limit + cache | P0 | Host cost ≈ $0 at low scale |
| 18.1.4 | URL format: `kerno.sh/i/<base58-8-char-id>` - short, branded, unambiguous | P0 | |
| 18.1.5 | Rendered page: static HTML, renders the incident like `kerno doctor` output, plus causal timeline diagram, plus "Run kerno on your cluster" CTA footer | P0 | Every page is a landing page |
| 18.1.6 | Optional short TTL: shares expire after 30 days unless claimed with a free account (email only, no password) | P1 | Keeps storage bounded, gives us an email list |
| 18.1.7 | `kerno share list` / `kerno share revoke <id>` for lifecycle management from CLI | P1 | |
| 18.1.8 | Self-hostable: publish `share-server` as a second binary so enterprises can run it on their infra with `--share-endpoint` pointing at it | P0 | Removes the privacy objection for regulated users |

**Definition of Done - 18.1**
- [ ] `kerno doctor --share` on a stressed VM returns a working `kerno.sh/i/xyz` URL within 2s
- [ ] Rendered page matches the terminal output at least 95% visually and includes the causal timeline
- [ ] Self-hosted mode works against a local share-server with `--share-endpoint=http://localhost:8787`
- [ ] Redaction removes all pod IPs and hostnames - verified by automated diff test

---

### 18.2 Incident CRD - *native Kubernetes object*

> `kubectl get incidents -n payments` / `kubectl describe incident checkout-latency-xyz`. Instantly native to Backstage, ArgoCD, k9s, Lens, Headlamp - every K8s tool that shows CRDs gets kerno for free.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 18.2.1 | CRD schema `incidents.kerno.io/v1alpha1` with fields: `severity`, `rootCause`, `blastRadius`, `causalTimeline`, `affectedWorkloads`, `shareUrl`, `discoveredAt`, `resolvedAt` | P0 | `pkg/apis/kerno/v1alpha1/` |
| 18.2.2 | `kubectl krew`-compatible printer columns: `NAME`, `SEVERITY`, `ROOT CAUSE`, `AGE` | P0 | First impression matters |
| 18.2.3 | When kerno finds a critical/high severity, it creates an Incident object in the affected pod's namespace | P0 | `internal/k8s/incidentwriter.go` |
| 18.2.4 | Incident auto-resolves: kerno updates `status.resolvedAt` when the signals underlying the root cause go clean for N minutes | P0 | Feedback loop, not just a one-shot alert |
| 18.2.5 | Retention: Incident objects TTL after 7 days by default (configurable); historical store is the Pattern DB (Phase 15), not etcd | P0 | Don't bloat etcd |
| 18.2.6 | RBAC: separate ServiceAccount with minimal CRUD on `incidents.kerno.io` - documented in Helm chart values | P0 | Enterprise security review bait |
| 18.2.7 | Events: kerno also emits standard Kubernetes Events linked to affected pods, so `kubectl describe pod` surfaces kerno findings without the CRD | P1 | Dual visibility |
| 18.2.8 | Optional webhook mode: post to a configurable URL on Incident create/update for custom routing | P1 | |

**Definition of Done - 18.2**
- [ ] `kubectl get incidents -A` lists active incidents with sensible printer columns
- [ ] Incidents auto-resolve when the underlying signals recover
- [ ] An Incident object shows up unprompted in Backstage / ArgoCD / k9s without any per-tool adapter code

---

### 18.3 Chat & Paging Sinks *(Slack / Discord / PagerDuty)*

> `helm install kerno --set slack.webhook=...` and incidents arrive in your team channel. One install, lifetime brand hits per channel.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 18.3.1 | Pluggable sink interface: `type Sink interface { Send(ctx, Incident) error }` in `internal/sinks/` | P0 | Keeps adapters small |
| 18.3.2 | Slack webhook sink with rich Block Kit formatting - severity color, causal timeline as a code block, "Open in kerno.sh" button pointing at the share URL | P0 | The button *is* the viral loop |
| 18.3.3 | Discord webhook sink - similar format, Embed-based | P1 | |
| 18.3.4 | PagerDuty events v2 integration - dedup_key = incident ID, auto-resolve when CRD resolves | P1 | Enterprise table stakes |
| 18.3.5 | Opsgenie sink | P2 | |
| 18.3.6 | Teams / Google Chat via generic webhook sink | P2 | |
| 18.3.7 | Per-severity routing: `critical → pagerduty+slack`, `high → slack`, `info → dropped` - configured in Helm values | P0 | Avoid alert fatigue from day one |
| 18.3.8 | Deduplication: one message per incident *object*, not per `doctor` run - CRD-backed state | P0 | No spam |
| 18.3.9 | Rate limiter: max N messages per sink per minute, dropped messages logged to `kerno_sink_dropped_total` | P0 | |

**Definition of Done - 18.3**
- [ ] Slack message for a synthetic incident shows severity, root cause, causal timeline, and a working `kerno.sh/i/xyz` link
- [ ] The same incident does not produce duplicate messages on repeated doctor runs
- [ ] Disabling all sinks still works - nothing breaks when no sink is configured

---

### 18.4 GitHub Action - `lowplane/kerno-action@v1`

> Every PR in an adopting repo runs kerno against a preview environment, posts findings as a PR comment, green ✓ badge when clean. Persistent brand presence inside the dev workflow.

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 18.4.1 | Composite action: install kerno, run `kerno doctor --json` against the supplied `kubeconfig`, emit the report | P0 | `.github/actions/kerno/action.yml` in a separate `lowplane/kerno-action` repo |
| 18.4.2 | PR comment formatter: post or update a single sticky comment with findings, not one per run (prevents comment spam) | P0 | Use `peter-evans/create-or-update-comment` pattern |
| 18.4.3 | Exit-code gate: configurable `fail-on: critical\|high\|any` to block merges on findings | P0 | |
| 18.4.4 | Status check: publishes a `kerno / doctor` status check so branch protection rules can require it | P0 | |
| 18.4.5 | Example workflow in README showing kind cluster spin-up → apply manifests → run kerno → fail on critical | P0 | Copy-paste adoption |
| 18.4.6 | Preview environment helper: `kerno chaos --induce` integration so users can test the action without a real incident | P1 | Works with Phase 8.5.1 |
| 18.4.7 | GitHub Marketplace listing with badges and screenshots | P1 | |

**Definition of Done - 18.4**
- [ ] Action runs green on a demo repo against a kind cluster
- [ ] A forced-failure case posts a readable PR comment with causal timeline
- [ ] The action is published on GitHub Marketplace

---

### 18.5 Comparison & Content Pages - `kerno.sh/vs/...`

> Honest comparison pages are HN catnip. Framing: "here's when to use what", not "we win."

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 18.5.1 | `kerno.sh/vs/cilium` - "Cilium shows traffic. Kerno explains incidents. Run both." | P1 | Non-adversarial; Cilium team might even share it |
| 18.5.2 | `kerno.sh/vs/pixie` - focus on causal-timeline differentiation | P1 | |
| 18.5.3 | `kerno.sh/vs/datadog` - "kerno is your free first-responder, Datadog is your long-term storage" | P1 | Complement, don't replace |
| 18.5.4 | `kerno.sh/vs/parca` - profiler vs incident diagnostician | P2 | |
| 18.5.5 | `kerno.sh/gallery` - 10 famous outages annotated with "what kerno would have shown" (Datadog Oct 2023, Cloudflare June 2022, Fastly 2021, etc). Public domain post-mortems only. | P1 | Evergreen content marketing |
| 18.5.6 | Blog post per shipped doctor rule: "How Kerno detects FD leaks from kernel data" - technical but accessible | P1 | Long-tail SEO |
| 18.5.7 | Short YouTube demo (<3 min) embedded on landing page and every /vs page | P2 | |

**Definition of Done - 18.5**
- [ ] Three `/vs/` pages live with honest comparisons that don't misrepresent the other tools
- [ ] `kerno.sh/gallery` has ≥5 annotated incidents
- [ ] At least one `/vs/` page gets 1k+ views (HN or shared by a competitor)

---

### 18.6 Ecosystem Discoverability *(low-effort plumbing)*

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 18.6.1 | **Promote Phase 14.6 Krew submission** to P1 after demo GIF ships - no point submitting before the viral asset exists | P1 | |
| 18.6.2 | Artifact Hub listing for the Helm chart | P1 | |
| 18.6.3 | Operator Hub listing (if Phase 18.2 CRD ships) | P2 | |
| 18.6.4 | awesome-ebpf / awesome-kubernetes PR adding kerno | P1 | |
| 18.6.5 | CNCF landscape submission (post-launch, once ≥500 stars) | P2 | |
| 18.6.6 | `kerno.io` domain redirect to `kerno.sh` or vice versa - consolidate brand | P2 | |

### Definition of Done - Phase 18

- [ ] `kerno doctor --share` is a one-liner that produces a shareable URL
- [ ] Incident CRD appears in kubectl / k9s / Backstage without any per-tool work
- [ ] At least one chat sink (Slack) is production-ready with rich formatting
- [ ] GitHub Action is listed on GitHub Marketplace and has a working example repo
- [ ] At least one `/vs/` comparison page is live and linked from the README
- [ ] **Every incident kerno finds leaves a brand-visible trail.** If a user runs `kerno doctor` and nothing about it propagates outside that terminal, Phase 18 has failed.

---

## Milestone Summary

| Milestone | Target | Key Deliverable | Success Metric |
|-----------|--------|-----------------|----------------|
| **M0: Skeleton** ✅ | Week 1 | `make build` works, CI green | Repo is cloneable and buildable |
| **M1: eBPF Core** ✅ | Week 3 | All 6 BPF programs scaffolded + Go loaders | Stubs compile, real events pending |
| **M2: Collectors** ✅ | Week 4 | Signal types + Registry | Types defined, live impls pending |
| **M3: Doctor** ✅ | Week 6 | Engine + 9 rules + renderers + 28 tests | Wired into CLI, needs live collectors |
| **M4: CLI** 🚧 | Week 7 | doctor/explain/predict/start/version done | trace/watch/audit pending |
| **M5: Prometheus** | Week 8 | `/metrics` endpoint | Grafana can graph kerno data |
| **M6: Adapters** | Week 9 | K8s + systemd + bare-metal enrichment | Pod names in metrics |
| **M7: K8s Deploy** | Week 10 | Helm chart + DaemonSet working | `helm install` on real cluster |
| **M7.5: Bare-Metal/VM** | Week 10 | curl installer + systemd unit + bare-metal compat | `curl \| bash` installs on any Linux, `kerno doctor` works without K8s |
| **M8: README** | Week 10 | README + demo GIF + quickstart | First external contributors |
| **M10: Signal Coverage** 🔴 | Month 3–4 | 69 doctor rules, 15+ eBPF programs, full K8s context | Detects every common K8s system-level incident: cgroup throttle, DNS, crashes, locks, kernel health, TCP drops, node pressure, NIC saturation, CPU steal, service mesh, IPVS, clock drift, container runtime |
| **M9: Hardening** | Week 12 | Tests + benchmarks + security review | ≥80% coverage, <1% CPU |
| **M11: SLO** | Month 4–5 | KernelSLO CRD + budget tracking | Error budgets from kernel signals |
| **M12: KEDA** | Month 5–6 | Kernel-aware autoscaling | Pods scale on disk latency |
| **M13: CNCF** | Month 6–7 | Sandbox application submitted | Application accepted |
| **M14: Causal Timeline** | Month 5–6 | `kerno doctor` with "How this unfolded" block + `--watch` mode + "What Changed" detector | Causal timeline shows correct ordered chain on synthetic incident; minimal `kerno topology --pod` shows supporting context |
| **M15: Pattern DB** | Month 6–7 | Embedded BoltDB pattern store + matcher | Synthetic incident matches stored pattern ≥ 0.8 |
| **M16: Remediation** | TBD (trust gate) | Three-tier engine + feedback loop | 50 successful Tier 1 actions in production after ≥10 clusters × ≥6 months clean |
| **M17: LLM Comms** | After M15 | Incident summary + runbook generation (bounded scope - never decides) | Non-kernel engineer reads summary and understands the incident |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| eBPF verifier rejects programs on older kernels | Medium | High | Use tracepoints over kprobes; test on 5.8, 5.15, 6.1 |
| Ring buffer drops under high load | Medium | Medium | Per-CPU sampling, configurable sample rate |
| K8s adapter memory explosion on large clusters | Low | High | Bounded LRU pod cache, informer resource version |
| Prometheus cardinality bomb (too many label combos) | Medium | High | Hard cap on unique label sets per metric |
| Privileged DaemonSet rejection by security teams | High | High | Document exact caps needed; support non-privileged mode with CAP_BPF |
| Scope creep: building features nobody uses | Medium | High | Doctor first. Everything else proves value through doctor. |
| Auto-remediation erodes trust before it's earned | High | Critical | Phase 16 trust gate; default Tier 3; per-namespace opt-in; kill switch; dual-control on Tier 2 |
| Topology graph cardinality explosion on large clusters | Medium | High | Per-namespace edge cap; TTL decay; reuse `LabelCardinalityLimit` pattern |
| Pattern false positives drive wrong remediation | Medium | High | Feedback loop; no auto-retry; blast-radius gate; confidence decay |
| LLM hallucinates a remediation action | Low | Critical | Hard scope boundary in Phase 17 - LLMs never decide actions, only describe them |
| `tcp_drop` tracepoint missing on older kernels | Medium | Low | Gate Phase 14.7 on kernel ≥ 5.17; degrade gracefully |
| Phase 10 scope creep - too many signals, none fully polished | High | High | Ship in sub-phases: cgroup+memory first (10.1+10.4), then DNS (10.2), then TCP expansion (10.3). Each sub-phase must pass tests before starting next. |
| Cgroup v1 vs v2 incompatibility | Medium | High | Target cgroup v2 only (K8s 1.25+ default). Document cgroup v1 as unsupported. Graceful skip on v1. |
| Lock contention tracepoint missing on kernel < 5.17 | Medium | Medium | Fall back to futex-only tracking. Document kernel version requirements per signal. |
| DNS eBPF parsing too complex for verifier | Medium | Medium | Keep DNS parser minimal - header only, no full domain parsing in eBPF. Do string assembly in userspace. |
| Too many doctor rules = noisy output | Medium | High | Tier rules: always-on (top 25), opt-in (rest). `kerno doctor --all` enables everything. Default is curated. |
| Kubelet config varies across distros (k3s, kind, EKS, GKE) | High | Medium | Read kubelet config from multiple paths. Fallback to sane defaults (100Mi mem, 10% disk, 15% imagefs). |
| IPVS not available (iptables mode clusters) | Medium | Low | Detect kube-proxy mode. Skip IPVS rules gracefully on iptables clusters. Still useful via conntrack. |
| Service mesh detection is brittle (envoy vs linkerd vs custom) | Medium | Medium | Detect by well-known process names + port patterns. Make sidecar detection configurable. |
| CPU steal = 0 on bare metal (rule never fires) | Low | Low | Rule gracefully returns nil when steal is 0. Only relevant on VMs. |
| Clock drift detection requires NTP daemon running | Low | Low | Fall back to kernel `adjtimex()` when chrony/ntpd not present. Always works. |
| **Demo GIF is mediocre** - the most important risk | High | Critical | Treat the GIF as a P0 feature, not a chore. Spend 20% of total effort. Re-record on every doctor-output change. Per principle #8. |
| Causal timeline produces wrong cause-and-effect chains | Medium | High | Curated dependency edges (not learned); explicit `confidence: high \| inferred` label on every timeline; never claim a cause we can't justify |
| Building topology UI features that compete with Cilium | Medium | Medium | Principle #7. Topology stays as plumbing. Anyone proposing `--unexpected`, DOT export, or a topology dashboard gets pointed at this row. |
| Spending energy on Krew submission before having users | Low | Medium | Defer Krew to post-launch. Marketing channels only matter if the product already works. |

---

## Technical Decisions Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language (userspace) | **Go** | cilium/ebpf library, single binary, cloud-native ecosystem alignment |
| Language (eBPF) | **C** | Only supported language for kernel BPF programs pre-Rust |
| BPF library | **cilium/ebpf** | Pure Go, no CGo, production-tested (Cilium, Cloudflare) |
| CLI framework | **cobra** | Industry standard, auto-completions, used by kubectl/docker |
| Config | **viper** | File + env + flags, pairs with cobra |
| Metrics | **prometheus/client_golang** | CNCF standard, Grafana integration |
| Logging | **log/slog** (stdlib) | No dependency, structured, sufficient |
| Histogram | **HDR Histogram** | Accurate percentiles at scale, fixed memory |
| Code generation | **bpf2go** | Official cilium/ebpf toolchain |
| Tracepoints vs kprobes | **Tracepoints preferred** | Stable kernel ABI, less likely to break across versions |
| Ring buffer vs perf buffer | **Ring buffer** | Single buffer, ordered events, lower overhead (requires kernel 5.8+) |
| Container image base | **distroless/static** | Minimal attack surface, no shell, tiny size |
| License | **Apache 2.0** | CNCF requirement, permissive, enterprise-friendly |

---

## Implementation Order (What To Code First)

This is the **exact order** to write code for maximum momentum:

```
 1. go.mod + main.go + Makefile                        ← 30 min
 2. version.go (--version flag)                         ← 15 min  
 3. vmlinux.h generation                                ← 15 min
 4. kerno.h (shared event structs)                      ← 30 min
 5. syscall_latency.c (simplest BPF program)            ← 2 hrs
 6. syscall_latency.go (bpf2go loader)                  ← 1 hr
 7. `kerno trace syscall` command (prove events flow)   ← 2 hrs
    ──── YOU NOW HAVE A WORKING eBPF TOOL ────
 8. tcp_monitor.c + loader                              ← 3 hrs
 9. oom_track.c + loader                                ← 2 hrs
10. disk_io.c + loader                                  ← 2 hrs
11. sched_delay.c + loader                              ← 2 hrs
12. fd_track.c + loader                                 ← 2 hrs
13. Collector interface + SyscallCollector              ← 3 hrs
14. Aggregation (HDR histogram percentiles)             ← 3 hrs
15. Remaining collectors (TCP, OOM, Disk, Sched, FD)    ← 6 hrs
    ──── YOU NOW HAVE ALL SIGNAL DATA ────
16. doctor.Engine (collect-evaluate-rank-render)        ← 4 hrs
17. Doctor rules (all 10)                               ← 6 hrs
18. Pretty renderer (colored terminal output)           ← 4 hrs
19. JSON renderer                                       ← 1 hr
20. `kerno doctor` CLI command                          ← 1 hr
    ──── KERNO DOCTOR WORKS ────
21. stress-test.sh (real cascade: disk → DB → API)      ← 4 hrs
22. README.md                                           ← 3 hrs
23. demo.tape + record `kerno doctor` GIF (the asset)   ← 6 hrs
24. Landing page (kerno.lowplane.dev) + install widget  ← 4 hrs
    ──── REPO IS SHAREABLE - PRINCIPLE #8 SATISFIED ────
23. Config system (viper)                               ← 2 hrs
24. Remaining CLI commands                              ← 4 hrs
25. Prometheus exporter                                 ← 4 hrs
26. K8s adapter                                         ← 6 hrs
27. Bare-metal + systemd adapters                       ← 2 hrs
28. `kerno start` daemon mode                           ← 3 hrs
29. Dockerfile                                          ← 1 hr
30. Helm chart + K8s manifests                          ← 4 hrs
31. CI pipeline (GitHub Actions)                        ← 2 hrs
32. Tests (target 80% coverage)                         ← 8 hrs
33. Performance benchmarks                              ← 4 hrs
    ──── v0.1 RELEASE ────

    ── Phase 10 - Complete Signal Coverage (the credibility gap) ──
34. Cgroup-to-pod resolver (cgroup path → pod/ns/container)      ← 6 hrs
35. CgroupCollector (cpu.stat, memory.events, io.pressure)       ← 6 hrs
36. Doctor rules: cpu_throttled, memory_limit_pressure            ← 4 hrs
37. MemoryCollector (/proc/meminfo + per-process RSS tracking)   ← 4 hrs
38. page_fault.c eBPF program + PageFaultCollector               ← 4 hrs
39. Doctor rules: swap_thrashing, page_fault_storm, memory_leak  ← 3 hrs
40. DNS monitor eBPF program (udp port 53 filtering)             ← 6 hrs
41. DNSCollector + doctor rules: dns_slow, dns_fail, dns_timeout ← 4 hrs
42. Expand tcp_monitor.c: IPv6, all states, tcp_drop hook        ← 6 hrs
43. Doctor rules: tcp_conn_failures, tcp_drops, backlog_overflow ← 3 hrs
44. lock_contention.c + futex tracker eBPF                       ← 6 hrs
45. LockCollector + doctor rules: lock_contention, futex_storm   ← 3 hrs
46. Socket/conntrack/ephemeral port monitors (procfs polling)    ← 4 hrs
47. Doctor rules: socket_overflow, port_exhaust, conntrack_full  ← 3 hrs
48. kernel_health.c eBPF (printk tracepoint) + dmesg fallback   ← 4 hrs
49. Doctor rules: kernel_warning, hung_task, irq_storm           ← 3 hrs
50. process_lifecycle.c eBPF (sched_process_exit)                ← 4 hrs
51. Doctor rules: crash_loop, signal_storm, fork_bomb            ← 3 hrs
52. Filesystem monitors: inode, writeback, disk space, per-dev   ← 4 hrs
53. Doctor rules: inode_exhaust, writeback, disk_space, queue_sat← 3 hrs
54. Expand fd_track.c: per-type FD accounting                    ← 3 hrs
55. Expand syscall_latency.c: errno classification               ← 3 hrs
56. Doctor rules: enospc, econnrefused, enomem                   ← 2 hrs
57. K8s context enrichment: pod metadata cache + namespace filter← 6 hrs
58. Thermal/hardware monitors (sysfs polling)                    ← 2 hrs
59. Node pressure detectors (kubelet eviction thresholds)        ← 4 hrs
60. NIC stats collector (bandwidth, errors, drops per iface)     ← 3 hrs
61. CPU steal time + iowait + PSI pressure collector             ← 3 hrs
62. Container runtime health checker (containerd/CRI-O)          ← 3 hrs
63. Clock drift / NTP sync detector                              ← 2 hrs
64. Service mesh sidecar resource tracker (envoy/linkerd)        ← 4 hrs
65. IPVS/kube-proxy service connectivity monitor                 ← 4 hrs
66. Cgroup memory.high throttle + direct reclaim eBPF            ← 4 hrs
67. ARP table + veth pair health checks                          ← 2 hrs
68. Doctor rules for all new signals (10.14–10.21)               ← 6 hrs
    ──── v0.2 RELEASE (Complete K8s Signal Coverage - 69 rules) ────

    ── Phase 14 - Causal Timeline & Incident Context ──
51. Signal history ring buffer (per-signal, last 10 min)   ← 4 hrs
52. Threshold-crossing tracker                             ← 2 hrs
53. Causal timeline engine (reconstructor + scoring)       ← 8 hrs
54. Doctor renderer: "How this unfolded" block             ← 3 hrs
55. `kerno doctor --watch` mode + early-signal trends      ← 5 hrs
56. "What Changed" detector (deployments, configmaps)      ← 4 hrs
57. L4 flow tracker (plumbing for timeline + impact)       ← 6 hrs
58. Minimal `kerno topology --pod` (supporting CLI only)   ← 2 hrs
59. Cross-namespace cascade rule                           ← 3 hrs
60. `kubectl-kerno` plugin: fan-out + cluster aggregator   ← 6 hrs
61. Re-record all demo GIFs to show causal timeline        ← 4 hrs
    ──── v0.3 RELEASE (Causal Timeline + K8s UX) ────

    ── Phase 15 - Pattern Database ──
62. Pattern schema + BoltDB store                          ← 4 hrs
63. Pattern matcher + confidence math                      ← 4 hrs
64. `kerno incident record` + community bundle             ← 3 hrs
    ──── v0.4 RELEASE (Pattern DB) ────

    ── Phase 17 - Bounded LLM Communication ──
65. LLM incident summary + runbook generation              ← 4 hrs
    ──── v0.5 RELEASE (Bounded LLM) ────

    ── Deferred (after users + trust earned) ──
    Krew manifest submission (Phase 14.6.7)                ← 1 hr
    NetworkPolicy drop visibility (Phase 14.7.2)           ← 4 hrs
    --- TRUST GATE: ≥10 prod clusters, ≥6 months clean ---
    Phase 16 - Three-Tier Remediation                      ← deferred
```

**Total estimated effort to v0.1:** ~90-100 hours of focused coding.
**Total estimated effort to v0.2 (Complete K8s Signal Coverage - 69 rules):** ~220-240 hours (adds ~130 hrs for Phase 10 with K8s-native sections).
**Total estimated effort to v0.3 (Causal Timeline):** ~270-290 hours.

---

## Dependency List (Go Modules)

```
github.com/cilium/ebpf          # eBPF loader + code generation
github.com/spf13/cobra           # CLI framework
github.com/spf13/viper           # Configuration
github.com/prometheus/client_golang  # Prometheus metrics
github.com/HdrHistogram/hdrhistogram-go  # Percentile computation
github.com/fatih/color            # Terminal colors (or lipgloss)
github.com/briandowns/spinner     # CLI spinner during collection
k8s.io/client-go                  # Kubernetes API (only if K8s adapter enabled)
k8s.io/apimachinery               # K8s types
go.etcd.io/bbolt                  # Embedded pattern store (Phase 15)
sigs.k8s.io/controller-runtime    # Incident CRD writer (Phase 18.2)
```

## Dependency List (Build Tools)

```
clang >= 14                       # eBPF compilation
llvm >= 14                        # eBPF target support
libbpf-dev                        # BPF CO-RE headers
linux-headers-$(uname -r)         # Kernel headers  
bpftool                           # BTF dump, skeleton generation
go >= 1.22                        # Go toolchain
goreleaser                        # Release automation
golangci-lint                     # Linting
```

---

*This document is the execution plan. Follow it top-to-bottom. When in doubt, ship `kerno doctor` first.*
