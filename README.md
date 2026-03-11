<p align="center">
  <h1 align="center">KERNO</h1>
  <p align="center">
    <strong>eBPF-based kernel observability engine for Linux</strong>
  </p>
  <p align="center">
    <a href="https://github.com/lowplane/kerno/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/lowplane/kerno/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://goreportcard.com/report/github.com/lowplane/kerno"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/lowplane/kerno"></a>
    <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg"></a>
    <a href="https://github.com/lowplane/kerno/releases"><img alt="Release" src="https://img.shields.io/github/v/release/lowplane/kerno?include_prereleases"></a>
  </p>
</p>

---

Kerno traces **syscall latency**, **TCP flows**, **OOM events**, **disk I/O delays**, **scheduler stalls**, and **file descriptor leaks** — in real-time — and maps those signals directly to **SLO error budgets**.

One command. 30 seconds. A plain-English diagnosis of exactly what is wrong with your production system — from the kernel up.

```bash
sudo kerno doctor
```

```
╔═══════════════════════════════════════════════════════════════╗
║                        KERNO DOCTOR                          ║
║                  Kernel Diagnostic Engine                     ║
╚═══════════════════════════════════════════════════════════════╝

  Collecting kernel signals... ████████████████████████████ 30s

  🔴 CRITICAL  TCP retransmits at 12% — api-server → postgres
  🔴 CRITICAL  OOM kill — celery-worker (1023Mi / 1024Mi limit)
  🟡 WARNING   Disk fsync p99 = 280ms — /dev/nvme0n1
  🟡 WARNING   Scheduler delay p99 = 18ms — node CPU contention
  🟢 OK        Syscall latency nominal
  🟢 OK        File descriptor counts stable

  ┌─ Recommendations ─────────────────────────────────────────┐
  │ 1. Investigate TCP path between api-server and postgres   │
  │ 2. Increase celery-worker memory limit to 1.5Gi           │
  │ 3. Move postgres to node with faster storage              │
  └───────────────────────────────────────────────────────────┘
```

## Why Kerno

Every observability tool you use today lives at the **application layer**. The kernel sees problems **first** — elevated syscall latency, TCP retransmits, memory pressure — minutes before your APM notices.

Kerno is the **missing layer**:

| | Layer | K8s Required | SLO Mapping | Multi-Env |
|---|---|:---:|:---:|:---:|
| Prometheus | Application | No | No | No |
| Datadog APM | Application | No | Partial | No |
| Inspektor Gadget | Container | **Yes** | No | No |
| **Kerno** | **Kernel** | **No** | **Yes** | **Yes** |

## Features

| Feature | Status | Description |
|---|:---:|---|
| `kerno doctor` | 🚧 | 30-second automated kernel diagnostic |
| Syscall latency tracing | 🚧 | Per-syscall p50/p95/p99 via eBPF |
| TCP flow monitoring | 🚧 | Retransmits, RTT, connection lifecycle |
| OOM kill tracking | 🚧 | Pre-kill alerts with full process context |
| Disk I/O latency | 🚧 | Block I/O per-operation percentiles |
| Scheduler delay | 🚧 | CPU run queue latency (runqlat) |
| FD leak detection | 🚧 | Open/close delta tracking per process |
| Prometheus export | 🚧 | `/metrics` endpoint for Grafana |
| Web dashboard | 📋 | Real-time kernel signal visualization |
| SLO bridge | 📋 | Map kernel signals to error budgets |
| Kubernetes enrichment | 📋 | Pod/namespace/node context |

**Legend:** ✅ Done | 🚧 In Progress | 📋 Planned

## Quick Start

### Prerequisites

- Linux kernel ≥ 5.8 with BTF support
- Root privileges (or `CAP_BPF` + `CAP_PERFMON`)

### Install

```bash
# From source
git clone https://github.com/lowplane/kerno.git
cd kerno
make build
sudo ./bin/kerno doctor

# Docker
docker run --privileged --pid=host \
  ghcr.io/lowplane/kerno:latest doctor
```

### Usage

```bash
# 30-second kernel diagnostic
sudo kerno doctor

# Quick 10-second check
sudo kerno doctor --duration 10s

# JSON output for CI/CD (exits 1 on critical findings)
sudo kerno doctor --output json --exit-code

# Continuous monitoring
sudo kerno doctor --continuous --interval 60s

# Start as daemon with Prometheus metrics
sudo kerno start

# Start with web dashboard
sudo kerno start --dashboard
```

## How It Works

```
                 KERNEL SPACE (eBPF programs)
┌──────────────────────────────────────────────────┐
│  sys_enter/sys_exit ──► syscall latency          │
│  tcp_retransmit_skb ──► retransmit events        │
│  oom_kill_process   ──► OOM events               │
│  block_rq_*         ──► disk I/O latency         │
│  sched_wakeup/switch──► run queue delay          │
│            Ring Buffers (mmap, zero-copy)         │
└────────────────────┬─────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────┐
│              USER SPACE (Go)                      │
│  Collectors ──► Aggregation ──► Doctor Engine     │
│       │              │              │             │
│       ▼              ▼              ▼             │
│  Prometheus    SLO Engine     Terminal Report     │
│  :9090/metrics  (error budgets)  (pretty/JSON)   │
└──────────────────────────────────────────────────┘
```

Kerno uses **6 eBPF programs** attached to stable kernel tracepoints (and kprobes where no tracepoint exists). Events flow through ring buffers with zero-copy to Go userspace, where they are aggregated into percentile distributions and analyzed by diagnostic rules.

## Configuration

Kerno works out of the box with zero configuration. For custom setups:

```yaml
# /etc/kerno/config.yaml
log_level: info
log_format: text

collectors:
  syscall_latency: true
  tcp_monitor: true
  oom_track: true
  disk_io: true
  sched_delay: true
  fd_track: true
  file_audit: false

doctor:
  duration: 30s
  thresholds:
    syscall_p99_warning_ns: 100000000   # 100ms
    tcp_retransmit_pct: 2.0             # 2%
    oom_memory_pct: 90.0                # 90%

prometheus:
  enabled: true
  addr: ":9090"
```

Environment variables override config: `KERNO_LOG_LEVEL=debug`, `KERNO_PROMETHEUS_ADDR=:9091`, etc.

## Building from Source

```bash
# Requirements: Go 1.24+, clang, libbpf-dev, llvm

# Build (uses stub BPF — works without clang)
make build

# Full build with eBPF compilation
make build-ebpf

# Run tests
make test

# Run linter
make lint

# All quality checks
make check

# Build Docker image
make docker
```

## Project Structure

```
kerno/
├── cmd/kerno/           # Binary entry point
├── internal/
│   ├── bpf/             # eBPF loaders + Go event types
│   │   └── c/           # eBPF C programs + headers
│   ├── cli/             # Cobra CLI commands
│   ├── collector/       # Signal collection + aggregation
│   ├── config/          # Typed configuration
│   └── version/         # Build metadata
├── Makefile             # Build orchestration
├── Dockerfile           # Multi-stage container build
└── .goreleaser.yml      # Release automation
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development setup and prerequisites
- Commit message conventions (Conventional Commits)
- Code review process
- DCO sign-off requirement

## Security

For vulnerability reports, see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

**Kerno** is built by [Shivam Kumar](https://github.com/btwshivam) at [Lowplane](https://github.com/lowplane).
