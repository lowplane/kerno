# Kerno Architecture Guide

> A complete walkthrough of Kerno's implementation - from kernel-level eBPF programs to AI-powered diagnostics.
> Written for the developer who wants to understand every layer.

---

## Table of Contents

1. [What Is Kerno?](#1-what-is-kerno)
2. [The Big Picture](#2-the-big-picture)
3. [Repository Layout](#3-repository-layout)
4. [Layer 1 - eBPF Programs (The Kernel Side)](#4-layer-1--ebpf-programs-the-kernel-side)
   - [4.1 How eBPF Works](#41-how-ebpf-works)
   - [4.2 The Shared Header: kerno.h](#42-the-shared-header-kernoh)
   - [4.3 Program: syscall_latency.c](#43-program-syscall_latencyc)
   - [4.4 Program: tcp_monitor.c](#44-program-tcp_monitorc)
   - [4.5 Program: oom_track.c](#45-program-oom_trackc)
   - [4.6 Program: disk_io.c](#46-program-disk_ioc)
   - [4.7 Program: sched_delay.c](#47-program-sched_delayc)
   - [4.8 Program: fd_track.c](#48-program-fd_trackc)
5. [Layer 2 - Go BPF Loaders (Kernel-to-Userspace Bridge)](#5-layer-2--go-bpf-loaders-kernel-to-userspace-bridge)
   - [5.1 The Loader Interface](#51-the-loader-interface)
   - [5.2 How bpf2go Code Generation Works](#52-how-bpf2go-code-generation-works)
   - [5.3 The Stub System (Building Without Clang)](#53-the-stub-system-building-without-clang)
   - [5.4 Event Types in Go](#54-event-types-in-go)
6. [Layer 3 - Collector Framework (Aggregation)](#6-layer-3--collector-framework-aggregation)
   - [6.1 The Collector Interface](#61-the-collector-interface)
   - [6.2 The Registry](#62-the-registry)
   - [6.3 The Signals Struct](#63-the-signals-struct)
   - [6.4 Snapshot Types](#64-snapshot-types)
7. [Layer 4 - Doctor Engine (Diagnostics)](#7-layer-4--doctor-engine-diagnostics)
   - [7.1 The Engine Orchestrator](#71-the-engine-orchestrator)
   - [7.2 All 11 Diagnostic Rules (Deep Dive)](#72-all-11-diagnostic-rules-deep-dive)
   - [7.3 Finding Struct and Ranking Algorithm](#73-finding-struct-and-ranking-algorithm)
   - [7.4 The Report Struct](#74-the-report-struct)
   - [7.5 Renderers: Pretty and JSON](#75-renderers-pretty-and-json)
   - [7.6 Prediction Engine](#76-prediction-engine)
8. [Layer 5 - AI Analysis (Optional Enrichment)](#8-layer-5--ai-analysis-optional-enrichment)
   - [8.1 Architecture: Why AI is a Post-Processing Layer](#81-architecture-why-ai-is-a-post-processing-layer)
   - [8.2 The Provider Interface](#82-the-provider-interface)
   - [8.3 Anthropic, OpenAI, Ollama Providers](#83-anthropic-openai-ollama-providers)
   - [8.4 The Analyzer: Bridging Doctor and AI](#84-the-analyzer-bridging-doctor-and-ai)
   - [8.5 Prompt Engineering](#85-prompt-engineering)
   - [8.6 Privacy Modes](#86-privacy-modes)
   - [8.7 Caching and Rate Limiting](#87-caching-and-rate-limiting)
   - [8.8 Fallback Analyzer (No LLM Required)](#88-fallback-analyzer-no-llm-required)
9. [Layer 6 - CLI (User Interface)](#9-layer-6--cli-user-interface)
   - [9.1 Root Command and Global Flags](#91-root-command-and-global-flags)
   - [9.2 kerno doctor - The Main Event](#92-kerno-doctor--the-main-event)
   - [9.3 kerno trace - Real-Time Event Streaming](#93-kerno-trace--real-time-event-streaming)
   - [9.4 kerno watch - Aggregated Monitoring](#94-kerno-watch--aggregated-monitoring)
   - [9.5 kerno start - Daemon Mode](#95-kerno-start--daemon-mode)
   - [9.6 kerno predict - Failure Prediction](#96-kerno-predict--failure-prediction)
   - [9.7 kerno explain - AI Error Explainer](#97-kerno-explain--ai-error-explainer)
10. [Layer 7 - Configuration](#10-layer-7--configuration)
    - [10.1 Config Struct and Defaults](#101-config-struct-and-defaults)
    - [10.2 Precedence: Flags > Env > File > Defaults](#102-precedence-flags--env--file--defaults)
    - [10.3 Validation](#103-validation)
11. [How It All Connects: Data Flow](#11-how-it-all-connects-data-flow)
12. [Build System](#12-build-system)
13. [Testing Strategy](#13-testing-strategy)
14. [Design Principles](#14-design-principles)
15. [Glossary](#15-glossary)

---

## 1. What Is Kerno?

Kerno is an **eBPF-based kernel observability engine** for Linux. It attaches tiny programs to kernel hook points that monitor six dimensions of system health:

| Signal | What It Measures | Why It Matters |
|--------|-----------------|----------------|
| **Syscall Latency** | How long each system call takes | Slow syscalls = slow applications |
| **TCP Flows** | Connections, retransmits, round-trip time | Network issues crash microservices |
| **OOM Events** | Kernel killing processes for memory | Data loss, cascading failures |
| **Disk I/O** | Read/write/sync latency per device | Storage bottlenecks stall everything |
| **Scheduler Delays** | Time processes wait on CPU run queue | CPU contention = response time spikes |
| **FD Tracking** | File descriptor opens/closes per process | FD leaks → eventual process crash |

The flagship command is `sudo kerno doctor` - it collects signals for 30 seconds, evaluates them against diagnostic rules, and prints a ranked report of findings.

---

## 2. The Big Picture

```
                         THE KERNO DATA PIPELINE
                         ========================

    KERNEL SPACE                    USER SPACE
    ────────────                    ──────────

  ┌──────────────┐
  │  Tracepoints │     Ring Buffer     ┌──────────────┐
  │  & Kprobes   │ ──────────────────> │  BPF Loaders │
  │              │   (256KB per prog)  │  (Go, cilium) │
  │ 6 eBPF progs │                     └──────┬───────┘
  └──────────────┘                            │
                                              │ Raw events
                                              ▼
                                     ┌──────────────────┐
                                     │ Collector Registry │
                                     │ (aggregation)      │
                                     └──────┬───────────┘
                                            │
                                            │ Signals snapshot
                                            ▼
                                     ┌──────────────────┐
                                     │  Doctor Engine     │
                                     │  (11 rules)        │──── Deterministic, always runs
                                     └──────┬───────────┘
                                            │
                                            │ []Finding
                                            ▼
                                     ┌──────────────────┐
                                     │  AI Analyzer       │──── Optional, post-processing only
                                     │  (Anthropic/       │
                                     │   OpenAI/Ollama)   │
                                     └──────┬───────────┘
                                            │
                                            │ Enriched Report
                                            ▼
                                     ┌──────────────────┐
                                     │  Renderers         │
                                     │  (Pretty / JSON)   │
                                     └──────────────────┘
                                            │
                                            ▼
                                        TERMINAL
```

**Critical architectural rule:** AI NEVER touches the hot path. It only processes aggregated results after the deterministic engine has already run.

---

## 3. Repository Layout

```
kerno/
├── cmd/kerno/main.go              ← Binary entry point (4 lines)
│
├── internal/
│   ├── bpf/                       ← eBPF C programs + Go loaders
│   │   ├── c/                     ← C source files
│   │   │   ├── headers/
│   │   │   │   ├── vmlinux.h      ← Kernel type definitions (CO-RE)
│   │   │   │   └── kerno.h        ← Shared event structs & macros
│   │   │   ├── syscall_latency.c
│   │   │   ├── tcp_monitor.c
│   │   │   ├── oom_track.c
│   │   │   ├── disk_io.c
│   │   │   ├── sched_delay.c
│   │   │   └── fd_track.c
│   │   ├── loader.go              ← Loader interface
│   │   ├── events.go              ← Go event structs (match C exactly)
│   │   ├── gen_stub.go            ← Stub objects for non-eBPF builds
│   │   ├── syscall_latency.go     ← Go loader for syscall_latency
│   │   ├── tcp_monitor.go
│   │   ├── oom_track.go
│   │   ├── disk_io.go
│   │   ├── sched_delay.go
│   │   ├── fd_track.go
│   │   ├── events_test.go
│   │   └── *_bpfel.go             ← Generated by bpf2go (not in git)
│   │
│   ├── collector/                 ← Signal collection framework
│   │   ├── collector.go           ← Collector interface + Registry
│   │   ├── signals.go             ← All snapshot types + Percentiles
│   │   └── collector_test.go
│   │
│   ├── doctor/                    ← Diagnostic engine
│   │   ├── engine.go              ← Engine orchestrator + Analyzer interface
│   │   ├── finding.go             ← Finding struct, Report, RankFindings
│   │   ├── rules.go               ← All 11 diagnostic rules
│   │   ├── render.go              ← Pretty + JSON renderers
│   │   ├── predict.go             ← Trend analysis + failure prediction
│   │   ├── rules_test.go
│   │   └── render_test.go
│   │
│   ├── ai/                        ← LLM provider abstraction
│   │   ├── provider.go            ← Provider interface + factory
│   │   ├── anthropic.go           ← Claude provider (raw HTTP)
│   │   ├── openai.go              ← GPT provider (raw HTTP)
│   │   ├── ollama.go              ← Local LLM provider (raw HTTP)
│   │   ├── analyzer.go            ← DefaultAnalyzer (implements doctor.Analyzer)
│   │   ├── prompt.go              ← System prompt + user prompt builder
│   │   ├── cache.go               ← TTL response cache
│   │   ├── ratelimit.go           ← Token bucket rate limiter
│   │   └── fallback.go            ← Template analyzer (no LLM needed)
│   │
│   ├── cli/                       ← Cobra CLI commands
│   │   ├── root.go                ← Root command, config init, logging
│   │   ├── doctor.go              ← kerno doctor
│   │   ├── trace.go               ← kerno trace (parent)
│   │   ├── trace_syscall.go       ← kerno trace syscall
│   │   ├── trace_disk.go          ← kerno trace disk
│   │   ├── trace_sched.go         ← kerno trace sched
│   │   ├── watch.go               ← kerno watch (parent)
│   │   ├── watch_tcp.go           ← kerno watch tcp
│   │   ├── watch_oom.go           ← kerno watch oom
│   │   ├── watch_fd.go            ← kerno watch fd
│   │   ├── start.go               ← kerno start (daemon)
│   │   ├── explain.go             ← kerno explain (AI)
│   │   ├── predict.go             ← kerno predict
│   │   ├── version.go             ← kerno version
│   │   ├── bpfutil.go             ← Shared helpers (requireRoot, formatters)
│   │   ├── trace_test.go
│   │   └── watch_test.go
│   │
│   ├── config/                    ← Viper-based config
│   │   ├── config.go
│   │   └── config_test.go
│   │
│   └── version/                   ← Build metadata
│       └── version.go
│
├── Makefile                       ← Build, test, lint, eBPF compilation
├── go.mod / go.sum
├── .goreleaser.yml
└── .golangci.yml
```

---

## 4. Layer 1 - eBPF Programs (The Kernel Side)

### 4.1 How eBPF Works

eBPF (extended Berkeley Packet Filter) lets you run sandboxed programs inside the Linux kernel without modifying kernel source code or loading kernel modules. Here's what happens:

1. **You write** a small C program
2. **Clang compiles** it to eBPF bytecode (a special instruction set)
3. **The kernel verifier** checks the bytecode for safety (no infinite loops, no invalid memory access, no crashes)
4. **The kernel JIT compiler** translates bytecode to native machine code
5. **The program runs** whenever a specific kernel event fires (syscall, network packet, scheduler decision, etc.)

eBPF programs communicate with userspace via **maps** (shared key-value stores) and **ring buffers** (high-performance event queues).

**Why Kerno uses eBPF:**
- Near-zero overhead (runs inside the kernel, no context switching)
- No kernel module compilation required
- CO-RE (Compile Once, Run Everywhere) works across kernel versions
- Safe: the verifier prevents crashes

### 4.2 The Shared Header: kerno.h

Every eBPF program includes `kerno.h`, which defines:

```c
// Constants
#define TASK_COMM_LEN  16       // Process name length (Linux limit)
#define MAX_ENTRIES    8192     // Hash map capacity
#define RINGBUF_SIZE   (256 * 1024)  // 256 KB per ring buffer

// Event type discriminators (used in Go to pick the right decoder)
#define EVENT_SYSCALL_LATENCY  1
#define EVENT_TCP_MONITOR      2
#define EVENT_OOM_KILL         3
#define EVENT_DISK_IO          4
#define EVENT_SCHED_DELAY      5
#define EVENT_FD_TRACK         6
#define EVENT_FILE_AUDIT       7

// Macros to declare BPF maps
#define KERNO_RINGBUF(name) ...   // Ring buffer for events
#define KERNO_HASH(name, ...) ... // Hash map for state tracking
```

Each event struct is defined here AND mirrored exactly in Go (`events.go`). Field order, sizes, and padding must be identical - the kernel writes raw bytes and Go reads them without any serialization layer.

**vmlinux.h** is auto-generated from the running kernel's BTF (BPF Type Format) information. It contains the type definitions for kernel structs like `struct task_struct`, `struct tcp_sock`, etc. This enables CO-RE - programs compiled on one machine run on any kernel version.

### 4.3 Program: syscall_latency.c

**Purpose:** Measure how long every system call takes.

**Hook points:**
- `tracepoint/raw_syscalls/sys_enter` - fires when any syscall begins
- `tracepoint/raw_syscalls/sys_exit` - fires when any syscall returns

**How it works:**
```
1. sys_enter fires:
   - Get current PID/TID via bpf_get_current_pid_tgid()
   - Record timestamp in hash map: pid_tgid → bpf_ktime_get_ns()

2. sys_exit fires:
   - Look up entry timestamp from hash map
   - Calculate: latency = now - entry_timestamp
   - Filter noise: skip if latency < 1000ns (1 microsecond)
   - Reserve space in ring buffer
   - Fill syscall_event struct (pid, tid, syscall_nr, latency, ret, comm)
   - Submit to ring buffer
   - Delete hash map entry
```

**Event struct:**
```c
struct syscall_event {
    __u64 timestamp_ns;    // When the syscall completed
    __u64 latency_ns;      // How long it took
    __u64 cgroup_id;       // Container identification
    __u32 pid;             // Process ID
    __u32 tid;             // Thread ID
    __u32 syscall_nr;      // Which syscall (0=read, 1=write, 59=execve, etc.)
    __u32 ret;             // Return value (0 = success, negative = error)
    char  comm[16];        // Process name ("nginx", "postgres", etc.)
};
```

**Why this matters:** If `read()` suddenly takes 500ms instead of 1ms, something is very wrong. This catches it at the source.

### 4.4 Program: tcp_monitor.c

**Purpose:** Track TCP connection lifecycle, retransmits, and round-trip time.

**Hook points:**
- `tracepoint/tcp/tcp_retransmit_skb` - fires on every TCP retransmission
- `tracepoint/sock/inet_sock_set_state` - fires on TCP state changes (connect, close)

**How it works:**
```
1. inet_sock_set_state fires:
   - Filter: only AF_INET (IPv4)
   - newstate == ESTABLISHED (1) → emit TCP_EVENT_CONNECT
   - newstate == CLOSE (7) → emit TCP_EVENT_CLOSE
   - Extract: source/dest IP, ports, RTT from tcp_sock, retransmit count

2. tcp_retransmit_skb fires:
   - Extract connection info from sk_buff
   - Emit TCP_EVENT_RETRANSMIT with retransmit count
```

**Event struct:**
```c
struct tcp_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 saddr, daddr;    // IPv4 addresses (network byte order)
    __u16 sport, dport;    // Ports
    __u16 family;          // AF_INET
    __u8  event_type;      // 1=connect, 2=close, 3=retransmit, 4=rtt
    __u8  state;           // TCP state number
    __u32 rtt_us;          // Smoothed RTT in microseconds
    __u32 retransmits;     // Total retransmit count for this connection
    char  comm[16];
};
```

**Why this matters:** A retransmit rate above 2% means the network is dropping packets. High RTT means either the server is slow or the network is congested.

### 4.5 Program: oom_track.c

**Purpose:** Capture every OOM (Out of Memory) kill event with context about the victim process.

**Hook point:**
- `kprobe/oom_kill_process` - fires when the kernel decides to kill a process to free memory

Note: This uses a kprobe (not a tracepoint) because there's no stable tracepoint for OOM kills. Kprobes are less stable across kernel versions but work with CO-RE.

**How it works:**
```
1. oom_kill_process fires:
   - Read the victim task_struct via BPF_CORE_READ
   - Extract: PID, process name, OOM score
   - Extract memory info: total pages, RSS pages
   - Get the triggering PID (who caused the allocation that triggered OOM)
   - Submit oom_event to ring buffer
```

**Why this matters:** When the kernel kills your database process because another process ate all the memory, you need to know immediately.

### 4.6 Program: disk_io.c

**Purpose:** Measure block I/O latency per operation (read/write/sync).

**Hook points:**
- `tracepoint/block/block_rq_issue` - fires when a block request is issued to the device
- `tracepoint/block/block_rq_complete` - fires when the device completes the request

**How it works:**
```
1. block_rq_issue fires:
   - Get sector number from context
   - Store in hash map: sector → current timestamp

2. block_rq_complete fires:
   - Look up issue timestamp by sector number
   - Calculate: latency = now - issue_timestamp
   - Delete hash map entry
   - Fill disk_event: latency, sector, device, bytes, operation, PID, comm
   - Operation type comes from ctx->rwbs[0]: 'R', 'W', or 'S'
   - Submit to ring buffer
```

**Event struct (updated with PID/Comm):**
```c
struct disk_event {
    __u64 timestamp_ns;
    __u64 latency_ns;
    __u64 sector;
    __u32 dev;          // Device number (major:minor encoded)
    __u32 nr_bytes;     // Bytes transferred
    __u32 pid;          // Process that issued the I/O
    __u8  op;           // 'R' = read, 'W' = write, 'S' = sync
    __u8  _pad[3];      // Alignment padding
    char  comm[16];     // Process name
};
```

**Why this matters:** If `fsync()` takes 200ms, your database is bottlenecked on storage. This traces it at the block layer, below all filesystem caching.

### 4.7 Program: sched_delay.c

**Purpose:** Measure how long processes wait on the CPU run queue before being scheduled.

**Hook points:**
- `tracepoint/sched/sched_wakeup` - fires when a process is placed on the run queue
- `tracepoint/sched/sched_switch` - fires when the CPU switches to a process

**How it works:**
```
1. sched_wakeup fires:
   - Store in hash map: woken_pid → current timestamp

2. sched_switch fires:
   - Get next PID (the process being scheduled)
   - Look up wakeup timestamp
   - Calculate: runq_delay = now - wakeup_timestamp
   - Filter noise: skip < 1000ns
   - Submit sched_event to ring buffer
```

**Why this matters:** A run queue delay of 20ms means processes are waiting 20ms before they even start running. This is CPU contention - either too many processes or noisy neighbors.

### 4.8 Program: fd_track.c

**Purpose:** Track file descriptor opens and closes per process to detect FD leaks.

**Hook points:**
- `tracepoint/syscalls/sys_exit_openat` - fires after an `openat()` syscall completes
- `tracepoint/syscalls/sys_exit_close` - fires after a `close()` syscall completes

**How it works:**
```
1. sys_exit_openat fires:
   - Check ret > 0 (successful open, fd is the return value)
   - Emit FD_OP_OPEN event with pid, fd number, process name

2. sys_exit_close fires:
   - Check ret == 0 (successful close)
   - Emit FD_OP_CLOSE event with pid, fd number, process name
```

**Why this matters:** If a process opens 10 FDs/second more than it closes, it will eventually hit the ulimit (typically 65536) and crash. By tracking the delta, we can predict when this will happen.

---

## 5. Layer 2 - Go BPF Loaders (Kernel-to-Userspace Bridge)

### 5.1 The Loader Interface

Every eBPF program has a Go loader that manages its lifecycle:

```go
// internal/bpf/loader.go

type Loader interface {
    Name() string
    Load() (io.Closer, error)
    Events(ctx context.Context) (<-chan RawEvent, error)
}
```

- **`Load()`** compiles the eBPF bytecode, loads it into the kernel via the `cilium/ebpf` library, attaches to hook points, and opens the ring buffer reader. Returns an `io.Closer` that detaches everything when closed.

- **`Events(ctx)`** spawns a goroutine that continuously reads from the ring buffer and sends raw bytes to a Go channel. The channel is closed when the context is canceled.

**Example: SyscallLatencyLoader.Load()**
```go
func (l *SyscallLatencyLoader) Load() (io.Closer, error) {
    // 1. Load compiled eBPF objects into kernel
    l.objs = &syscallLatencyObjects{}
    loadSyscallLatencyObjects(l.objs, &ebpf.CollectionOptions{})

    // 2. Attach to tracepoints
    enterLink, _ := link.Tracepoint("raw_syscalls", "sys_enter", l.objs.TracepointSysEnter, nil)
    exitLink, _ := link.Tracepoint("raw_syscalls", "sys_exit", l.objs.TracepointSysExit, nil)

    // 3. Open ring buffer reader
    l.reader, _ = ringbuf.NewReader(l.objs.Events)

    return closerFunc(l.close), nil
}
```

### 5.2 How bpf2go Code Generation Works

Each loader file has a `//go:generate` directive:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I c/headers" -target bpfel -type syscall_event syscallLatency c/syscall_latency.c
```

When you run `make generate`, this:
1. Compiles `syscall_latency.c` to eBPF bytecode using clang
2. Generates `syscall_latency_bpfel.go` which contains:
   - The compiled bytecode embedded as a Go byte slice
   - A `syscallLatencyObjects` struct with typed fields for each map and program
   - A `loadSyscallLatencyObjects()` function that loads everything into the kernel

The generated files are NOT committed to git - CI generates them fresh.

### 5.3 The Stub System (Building Without Clang)

For development without clang/libbpf, `gen_stub.go` provides placeholder types:

```go
//go:build !ebpf

// Stub that returns an error when you try to load
func loadSyscallLatencyObjects(obj *syscallLatencyObjects, opts *ebpf.CollectionOptions) error {
    return fmt.Errorf("eBPF programs not compiled; run 'make generate' first")
}
```

The `!ebpf` build tag means these stubs are used by default. When you compile with real eBPF (`make generate`), the generated `_bpfel.go` files replace the stubs.

This means `go build ./...` works on any machine - you only need clang to actually run eBPF programs.

### 5.4 Event Types in Go

`events.go` defines Go structs that **exactly mirror** the C structs byte-for-byte:

```go
type SyscallEvent struct {
    TimestampNs uint64              // 8 bytes
    LatencyNs   uint64              // 8 bytes
    CgroupID    uint64              // 8 bytes
    PID         uint32              // 4 bytes
    TID         uint32              // 4 bytes
    SyscallNr   uint32              // 4 bytes
    Ret         uint32              // 4 bytes
    Comm        [TaskCommLen]byte   // 16 bytes
}                                   // Total: 56 bytes (matches C struct)
```

Decoding is simple binary read:
```go
func DecodeSyscallEvent(data []byte) (*SyscallEvent, error) {
    var event SyscallEvent
    binary.Read(bytes.NewReader(data), binary.LittleEndian, &event)
    return &event, nil
}
```

Each event type has helper methods:
- `CommString()` - converts null-terminated byte array to Go string
- `Latency()` / `RunqDelay()` / `RTT()` - converts nanosecond fields to `time.Duration`
- `SrcAddr()` / `DstAddr()` - converts uint32 to `net.IP`
- `OpString()` - converts operation byte to "read"/"write"/"sync"

---

## 6. Layer 3 - Collector Framework (Aggregation)

### 6.1 The Collector Interface

```go
// internal/collector/collector.go

type Collector interface {
    Name() string
    Start(ctx context.Context) error
    Stop()
    Snapshot() interface{}
}
```

A Collector sits between a BPF loader (raw events) and the doctor engine (aggregated snapshots). It:
1. Reads raw events from a BPF loader's event channel
2. Aggregates them over time windows (percentiles, counts, rates)
3. Produces a typed snapshot on demand

### 6.2 The Registry

The Registry manages all collectors:

```go
registry := collector.NewRegistry(logger)
registry.Register(syscallCollector)
registry.Register(tcpCollector)

registry.StartAll(ctx)    // Start all collectors
defer registry.StopAll()  // Graceful shutdown

signals := registry.Signals(30 * time.Second)  // Combined snapshot
```

`Signals()` iterates all collectors, calls `Snapshot()` on each, and assembles them into a unified `Signals` struct using a type switch:

```go
switch v := snap.(type) {
case *SyscallSnapshot:
    s.Syscall = v
case *TCPSnapshot:
    s.TCP = v
case *DiskIOSnapshot:
    s.DiskIO = v
// ...
}
```

### 6.3 The Signals Struct

This is the **single integration point** consumed by everything downstream:

```go
type Signals struct {
    Timestamp time.Time
    Duration  time.Duration
    Host      HostInfo

    Syscall *SyscallSnapshot    // nil if collector disabled
    TCP     *TCPSnapshot
    OOM     *OOMSnapshot
    DiskIO  *DiskIOSnapshot
    Sched   *SchedSnapshot
    FD      *FDSnapshot
    Memory  *MemorySnapshot
}
```

Doctor rules, AI prompts, exporters, and the dashboard all consume this same struct. This is a deliberate design decision - one snapshot format for the entire system.

### 6.4 Snapshot Types

**Percentiles** (used across all distribution-based snapshots):
```go
type Percentiles struct {
    P50 time.Duration   // Median
    P95 time.Duration   // 95th percentile
    P99 time.Duration   // 99th percentile (used for alerting)
    Max time.Duration   // Maximum observed
}
```

**SyscallSnapshot:** Per-(syscall, process) entries with count, error count, and latency percentiles.

**TCPSnapshot:** Active connections, total retransmits, retransmit rate (%), RTT percentiles, top retransmitters list.

**OOMSnapshot:** List of OOM events with victim process details. No aggregation - every OOM is critical.

**DiskIOSnapshot:** Separate latency percentiles for read, write, and sync operations. Counts and throughput (bytes).

**SchedSnapshot:** Global run queue delay percentiles, per-process top delayed list.

**FDSnapshot:** Total opens/closes, net delta, growth rate (FDs/sec), per-process entries.

**MemorySnapshot:** Used/total/available bytes, usage percentage, growth rate (bytes/sec), swap usage.

---

## 7. Layer 4 - Doctor Engine (Diagnostics)

### 7.1 The Engine Orchestrator

```go
// internal/doctor/engine.go

type Engine struct {
    thresholds config.DoctorThresholds  // Configurable trigger thresholds
    analyzer   Analyzer                 // nil = no AI
    logger     *slog.Logger
    history    []*collector.Signals     // Ring buffer of last 10 snapshots
    maxHistory int                      // 10
}
```

**`Diagnose(ctx, signals)`** is the core pipeline:

```
Phase 1: Evaluate(signals, thresholds) → []Finding    [deterministic, always runs]
Phase 2: analyzer.Analyze(signals, findings, history)  [optional, AI enrichment]
Phase 3: Build Report struct
Phase 4: Append signals to history ring buffer
```

Key behaviors:
- AI failure is **non-fatal** - the engine logs a warning and continues with rule-based results
- Only calls AI if there are actionable findings (WARNING or CRITICAL)
- Maintains a 10-snapshot history for continuous mode trend analysis

### 7.2 All 11 Diagnostic Rules (Deep Dive)

All rules live in `rules.go`. The `Evaluate()` function runs them sequentially and collects all findings:

```go
func Evaluate(s *collector.Signals, t config.DoctorThresholds) []Finding {
    var findings []Finding
    // Run each rule...
    findings = append(findings, evalDiskIOBottleneck(s, t)...)
    findings = append(findings, evalOOMKillOccurred(s)...)
    // ... all 9 rules ...

    // If nothing found, emit "healthy system"
    if len(findings) == 0 {
        findings = evalHealthySystem(s)
    }

    RankFindings(findings)
    return findings
}
```

Here are all 11 rules with their exact logic:

---

#### Rule 1: Disk I/O Bottleneck

**Signal:** `diskio` | **Trigger:** High sync or write latency

```
IF sync P99 ≥ DiskP99CriticalNs (200ms default):
    → CRITICAL "Disk I/O bottleneck: sync latency critical"
ELIF sync P99 ≥ DiskP99WarningNs (50ms default):
    → WARNING "Disk I/O bottleneck: sync latency elevated"

IF write P99 ≥ DiskP99CriticalNs (200ms default):
    → CRITICAL "Disk I/O bottleneck: write latency critical"
```

**Evidence:** `"sync P99=210ms (threshold: 200ms), 1523 sync ops"`
**Fix:** `["iostat -x 1 - identify the saturated device", "check I/O scheduler and queue depth", "consider faster storage or SSD"]`

---

#### Rule 2: OOM Kill Occurred

**Signal:** `oom` | **Trigger:** Any OOM event in the window

```
IF OOM.Count > 0:
    FOR EACH event:
        → CRITICAL "OOM kill: <process> (PID <pid>) was killed"
```

**Evidence:** `"oom_score=950, RSS=131072 pages, total=262144 pages"`
**Fix:** `["check memory limits: cat /proc/<pid>/cgroup", "profile memory: valgrind --tool=massif", "increase memory limit or add swap"]`

---

#### Rule 3: TCP Retransmit Storm

**Signal:** `tcp` | **Trigger:** Retransmit rate above threshold

```
IF RetransmitRate ≥ TCPRetransmitPct (2.0% default):
    → CRITICAL "TCP retransmit storm"
```

**Evidence:** `"retransmit rate=5.2% (threshold: 2.0%), 156 total retransmits, 42 active connections"`
**Fix:** `["ethtool -S <iface> - check NIC errors", "ping / mtr - check path quality", "ss -ti - inspect per-connection metrics"]`

---

#### Rule 4: TCP RTT Degradation

**Signal:** `tcp` | **Trigger:** RTT P99 above 10ms (hard-coded)

```
IF RTT.P99 > 10ms:
    → WARNING "TCP round-trip time degradation"
```

**Evidence:** `"RTT P99=25ms, P50=3ms (threshold: 10ms)"`

---

#### Rule 5: Scheduler Contention

**Signal:** `sched` | **Trigger:** Run queue delay exceeds thresholds

```
IF RunqDelay.P99 ≥ SchedDelayCriticalNs (20ms default):
    → CRITICAL "CPU scheduler contention: critical runqueue delays"
ELIF RunqDelay.P99 ≥ SchedDelayWarningNs (5ms default):
    → WARNING "CPU scheduler contention: elevated runqueue delays"
```

**Evidence:** `"runqueue P99=25ms, P50=2ms (warning: 5ms, critical: 20ms)"`
**Fix:** `["top -H -p <pid> - find thread count", "reduce thread/goroutine count", "check for noisy neighbors: cgroup CPU shares"]`

---

#### Rule 6: File Descriptor Leak

**Signal:** `fd` | **Trigger:** FD growth rate above threshold

```
IF GrowthRate ≥ FDGrowthPerSec (10.0 default):
    → WARNING "File descriptor leak detected"
    IF (65536 - NetDelta) / GrowthRate computable:
        → Set ETA to FD exhaustion
```

**ETA calculation:**
```
remaining_fds = 65536 - current_net_delta
eta_seconds = remaining_fds / growth_rate
Example: (65536 - 29072) / 20.0 = ~30 minutes
```

**Evidence:** `"growth rate=20.0 FDs/sec (threshold: 10.0), opens=1523, closes=523, net delta=+1000"`

---

#### Rule 7: Syscall Latency High

**Signal:** `syscall` | **Trigger:** Per-syscall P99 latency above thresholds

```
FOR EACH syscall entry:
    IF Latency.P99 ≥ SyscallP99CriticalNs (500ms default):
        → CRITICAL "High syscall latency: <name>() P99 above critical threshold"
    ELIF Latency.P99 ≥ SyscallP99WarningNs (100ms default):
        → WARNING "High syscall latency: <name>() P99 above warning threshold"
```

**Evidence:** `"read() P99=150ms, P50=2ms, count=45321 (threshold: 100ms)"`
**Process:** Associates the finding with the process making the slow calls

---

#### Rule 8: OOM Imminent

**Signal:** `memory` | **Trigger:** Memory usage above threshold with positive growth

```
IF UsedPct > 95% AND GrowthRateBytesPerSec > 0:
    → CRITICAL "OOM imminent: memory critically low and growing"
    ETA = AvailableBytes / GrowthRateBytesPerSec
ELIF UsedPct ≥ OOMMemoryPct (90% default):
    → WARNING "Memory pressure: approaching OOM threshold"
```

**ETA calculation:**
```
available_bytes = 500MB
growth_rate = 20MB/sec
eta = 500MB / 20MB/sec = 25 seconds
```

---

#### Rule 9: Syscall Error Rate

**Signal:** `syscall` | **Trigger:** Per-syscall error rate above thresholds

```
FOR EACH syscall entry with Count > 0:
    error_rate = ErrorCount / Count * 100
    IF error_rate ≥ 10.0%:
        → CRITICAL "High syscall error rate: <name>()"
    ELIF error_rate ≥ 1.0%:
        → WARNING "Elevated syscall error rate: <name>()"
```

---

#### Rule 10: Healthy System

**Trigger:** No other rules fired

```
IF len(findings) == 0:
    → INFO "All kernel signals within normal thresholds"
```

This is the positive case - confirming that monitoring is working and everything looks good.

---

### 7.3 Finding Struct and Ranking Algorithm

```go
type Finding struct {
    Severity   Severity          // INFO, WARNING, CRITICAL
    Rule       string            // "disk_io_bottleneck", "oom_kill", etc.
    Title      string            // Short headline
    Signal     string            // "diskio", "tcp", "syscall", etc.
    Cause      string            // Plain English explanation
    Impact     string            // What breaks because of this
    Evidence   string            // Raw metrics supporting the finding
    Fix        []string          // Ordered remediation steps
    ETA        *time.Duration    // Time to failure (nil if not applicable)
    Metric     string            // Specific metric name
    Value      float64           // Observed value
    Threshold  float64           // Configured threshold
    Process    string            // Associated process name
}
```

**The `RankFindings()` algorithm sorts by:**
1. **Severity descending** - CRITICAL (2) before WARNING (1) before INFO (0)
2. **ETA ascending** - shortest time to failure first (most urgent)
3. **Has ETA** before doesn't have ETA - a ticking clock is more urgent
4. **Threshold breach ratio** - value/threshold ratio descending (how badly is the threshold exceeded?)

Result: A CRITICAL finding with a 5-minute ETA sorts before a CRITICAL with no ETA, which sorts before a WARNING.

### 7.4 The Report Struct

```go
type Report struct {
    Hostname        string
    KernelVer       string
    Arch            string
    StartTime       time.Time
    EndTime         time.Time
    Duration        time.Duration
    Findings        []Finding         // Already ranked
    EventsCollected uint64
    ProgramsLoaded  int
    Analysis        *AnalysisResponse // nil if no AI
}

func (r *Report) HasCritical() bool     // Used by --exit-code
func (r *Report) CountBySeverity() (critical, warning, info int)
```

### 7.5 Renderers: Pretty and JSON

Both implement the `Renderer` interface:
```go
type Renderer interface {
    Render(w io.Writer, report *Report) error
}
```

**PrettyRenderer** produces terminal output:
```
╔═══════════════════════════════════════════════════════════╗
║                     KERNO DOCTOR                         ║
╚═══════════════════════════════════════════════════════════╝

  Host:     myserver.local
  Kernel:   6.1.0-generic
  Analyzed: 15:30:00 → 15:30:30 (30s window)

────────────────────────────────────────────────────────────
 FINDINGS  (2 critical, 1 warning, 0 info)
────────────────────────────────────────────────────────────

!! CRITICAL  Disk I/O bottleneck: sync latency critical
  ──────────────────────────────────────
  Signal:   diskio
  Cause:    Disk sync operations are taking >200ms...
  Impact:   Applications waiting on fsync() will stall...
  Evidence: sync P99=210ms (threshold: 200ms), 1523 sync ops
  Fix:      → iostat -x 1 - identify the saturated device
            → check I/O scheduler and queue depth

 RECOMMENDED ACTION ORDER
  1. [NOW]     Disk I/O bottleneck: sync latency critical
  2. [5 MIN]   High syscall latency: fsync()
  3. [MONITOR] TCP round-trip time degradation
```

**JSONRenderer** produces machine-readable output for CI/CD:
```json
{
  "hostname": "myserver.local",
  "findings": [
    {
      "severity": "CRITICAL",
      "rule": "disk_io_bottleneck",
      "title": "Disk I/O bottleneck: sync latency critical",
      "evidence": "sync P99=210ms ...",
      "fix": ["iostat -x 1", "check queue depth"]
    }
  ],
  "summary": {"critical": 2, "warning": 1, "info": 0}
}
```

### 7.6 Prediction Engine

`predict.go` uses **linear regression** on multiple signal snapshots to predict future failures:

```go
func Predict(snapshots []*collector.Signals) *PredictionReport
```

**Four prediction functions:**

| Predictor | What it watches | Critical threshold | Example |
|-----------|----------------|-------------------|---------|
| `predictFDExhaustion` | FD net delta growth | 65536 (ulimit) | "FD exhaustion in ~30m" |
| `predictDiskSaturation` | Sync latency P99 | 200ms | "Disk saturated in ~15m" |
| `predictSchedDegradation` | Runq delay P99 | 20ms | "CPU contention critical in ~45m" |
| `predictTCPDegradation` | Retransmit rate | 2.0% | "TCP storm in ~20m" |

**Math:**
- `linearSlope()` - least-squares regression on the metric values across snapshots
- `rateConsistency()` - coefficient of variation (how stable is the trend?)
- Confidence = inverted CV, clamped to [0.3, 0.95]

---

## 8. Layer 5 - AI Analysis (Optional Enrichment)

### 8.1 Architecture: Why AI is a Post-Processing Layer

This is a **critical design decision**:

```
WRONG:  eBPF events → AI → diagnostic output
RIGHT:  eBPF events → deterministic rules → output ──→ AI enrichment (optional)
```

Reasons:
- **Reliability:** The rule engine always works, even without internet
- **Latency:** LLM calls take 2-5 seconds; rules evaluate in microseconds
- **Cost:** LLM calls cost money; rules are free
- **Determinism:** Same inputs → same outputs, every time
- **Safety:** AI never sees raw kernel events, only aggregated summaries

### 8.2 The Provider Interface

```go
// internal/ai/provider.go

type Provider interface {
    Name() string
    Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
}
```

**No LLM SDK dependencies.** All three providers use `net/http` + `encoding/json`. This is intentional - SDKs add weight, version conflicts, and often break.

### 8.3 Anthropic, OpenAI, Ollama Providers

| Provider | Default Model | Default Endpoint | Auth | Notes |
|----------|--------------|-----------------|------|-------|
| **Anthropic** | `claude-sonnet-4-20250514` | `api.anthropic.com` | `x-api-key` header | API version `2023-06-01` |
| **OpenAI** | `gpt-4o-mini` | `api.openai.com` | `Authorization: Bearer` | Compatible with Azure, vLLM |
| **Ollama** | `llama3.1` | `localhost:11434` | None | Fully local, air-gapped |

Each provider:
1. Constructs an HTTP request with the appropriate format
2. Sends it to the endpoint
3. Parses the response to extract the text content and token count
4. Returns a `CompletionResponse`

### 8.4 The Analyzer: Bridging Doctor and AI

```go
// internal/ai/analyzer.go

type DefaultAnalyzer struct {
    provider Provider
    cache    *Cache
    privacy  PrivacyMode
    logger   *slog.Logger
}
```

The `Analyze()` pipeline:
```
1. Check cache (fingerprint = rule names + severities)
   → Cache hit? Return cached response.

2. Build user prompt via BuildUserPrompt(signals, findings, history, privacy)

3. Call provider.Complete(SystemPrompt, UserPrompt)

4. Parse JSON response (handle markdown code blocks)
   → JSON parse fails? Use raw text as plain summary (graceful degradation)

5. Cache the result

6. Return AnalysisResponse
```

The `Analyzer` interface is defined in the `doctor` package (not `ai`) to avoid import cycles:

```go
// internal/doctor/engine.go
type Analyzer interface {
    Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResponse, error)
}
```

The `ai.DefaultAnalyzer` implements this interface. The `doctor` package never imports `ai`.

### 8.5 Prompt Engineering

**System prompt** (in `prompt.go`): Instructs the LLM to act as "Kerno, a kernel diagnostics expert" and return structured JSON with:
- `summary`: 2-4 sentence plain-English diagnosis
- `correlations`: cross-signal patterns with confidence scores
- `rootCauses`: prioritized explanations with specific fix commands
- `anomalies`: deviations from baseline

**User prompt** (`BuildUserPrompt()`): Serializes data in a token-efficient compact format:
```
HOST: myserver.local, kernel 6.1.0, amd64
WINDOW: 30s ending 2026-04-04T15:30:30Z

FINDINGS (ranked):
[CRITICAL] diskio: Disk I/O bottleneck - process: postgres
           evidence: sync P99=210ms (threshold: 200ms)

RAW METRICS:
syscall: total=45321, top_slow=[fsync:150ms, read:45ms]
diskio: reads=1200, writes=3400, syncs=1523, sync_p99=210ms
tcp: active=42, retransmits=156, retransmit_rate=5.2%, rtt_p99=25ms

HISTORY (previous snapshots, oldest first):
  snapshot 1 (60s ago):
    diskio: sync_p99=180ms
  snapshot 2 (30s ago):
    diskio: sync_p99=195ms
```

### 8.6 Privacy Modes

| Mode | What's sent | What's hidden |
|------|------------|---------------|
| **full** | Everything: hostname, IPs, PIDs, process names | Nothing |
| **redacted** | Kernel version, all metrics | Hostname, IPs, PIDs |
| **summary** | Only aggregated numbers | All identifying information |

Configure via `KERNO_AI_PRIVACY_MODE=redacted` or config file.

### 8.7 Caching and Rate Limiting

**Cache** (`cache.go`):
- TTL-based, keyed by findings fingerprint (not exact values)
- Fingerprint: `"disk_io_bottleneck:CRITICAL|tcp_retransmit_storm:CRITICAL"`
- Same combination of triggered rules → cache hit
- Prevents redundant LLM calls in `--continuous` mode
- Lazy eviction when cache exceeds 100 entries

**Rate limiter** (`ratelimit.go`):
- Token bucket algorithm wrapping any Provider
- Configurable calls-per-minute (default: 10)
- Proportional token refill based on elapsed time
- Returns error when exhausted (caller handles gracefully)

### 8.8 Fallback Analyzer (No LLM Required)

When AI is disabled or the provider is unreachable, `FallbackAnalyzer` generates deterministic summaries from templates:

```go
func (f *FallbackAnalyzer) Analyze(ctx, req) (*AnalysisResponse, error) {
    // Count severities
    // Build summary from top finding
    // Detect simple correlations:
    //   diskio + syscall → "Disk I/O causing slow syscalls"
    //   tcp + syscall → "Network causing syscall latency"
    //   sched + diskio → "I/O wait causing CPU contention"
    //   fd + oom → "Resource exhaustion cascade"
    // Build root causes from WARNING+ findings
    // Return with confidence = 1.0 (deterministic)
}
```

---

## 9. Layer 6 - CLI (User Interface)

### 9.1 Root Command and Global Flags

```go
// internal/cli/root.go

func New() *cobra.Command {
    root := &cobra.Command{
        Use:   "kerno",
        Short: "Kernel-level observability engine for Linux",
        PersistentPreRunE: initConfig,  // Load config before any command
    }

    // Global flags available to all commands
    pf.StringVar(&cfgFile, "config", "", "config file path")
    pf.String("log-level", "info", "debug, info, warn, error")
    pf.String("log-format", "text", "text, json")
    pf.String("output", "pretty", "pretty, json")
    pf.Bool("no-color", false, "disable colored output")

    root.AddCommand(
        newDoctorCmd(), newExplainCmd(), newPredictCmd(),
        newVersionCmd(), newStartCmd(), newTraceCmd(), newWatchCmd(),
    )
    return root
}
```

`initConfig()` runs before every command:
1. Discovers config file (flag → `/etc/kerno/config.yaml` → `~/.kerno/` → `.`)
2. Binds environment variables (`KERNO_*`)
3. Unmarshals into typed `config.Config` struct
4. Validates configuration
5. Initializes structured logger (`log/slog`)

### 9.2 kerno doctor - The Main Event

```bash
sudo kerno doctor                         # 30-second diagnostic
sudo kerno doctor --duration 10s          # Quick check
sudo kerno doctor --output json --exit-code  # CI/CD mode
sudo kerno doctor --continuous --interval 60s  # Monitoring
sudo kerno doctor --ai                    # Enable AI enrichment
```

**Pipeline:**
1. Resolve config (duration, AI enabled, thresholds)
2. Build optional AI analyzer (non-fatal if fails)
3. Create doctor Engine with thresholds
4. Select renderer (Pretty or JSON)
5. Create collector registry
6. **Diagnostic cycle:**
   - Collect signals for `--duration`
   - `engine.Diagnose()` → rules + optional AI
   - Render report to stdout
   - If `--exit-code` and CRITICAL → exit 1
7. If `--continuous` → wait `--interval` → repeat

### 9.3 kerno trace - Real-Time Event Streaming

Trace commands load a single eBPF program and stream individual events:

```bash
sudo kerno trace syscall --pid 1234 --filter read
sudo kerno trace disk --op write --threshold 10ms --process postgres
sudo kerno trace sched --threshold 5ms --duration 30s
```

**Trace syscall** has two modes:
- **Stream mode** (default): Print one line per event
  ```
  [15:04:05] PID=1234   COMM=nginx           SYSCALL=read            LATENCY=1.23ms    RET=0
  ```
- **Top mode** (`--top 10`): Accumulate events, refresh display every 1s
  ```
  [15:04:05] Syscall Latency Top - 42 entries (last 1s)
  SYSCALL          PROCESS             COUNT        P50        P95        P99
  ──────────────────────────────────────────────────────────────────────────────
  fsync            postgres             1523      2.1ms      15ms       45ms
  read             nginx                8921      0.1ms      0.5ms      1.2ms
  ```

**Filter logic** (exported for testing):
- `matchSyscallFilter(event, filter)` - match by name ("read") or number ("0")
- `matchDiskOp(event, filter)` - match "read"/"write"/"sync" against Op byte
- `matchDiskProcess(event, filter)` - case-insensitive Comm match
- `matchOOMThreshold(event, threshold)` - OOM score comparison

### 9.4 kerno watch - Aggregated Monitoring

Watch commands aggregate events over time windows:

```bash
sudo kerno watch tcp --retransmits --interval 5s
sudo kerno watch oom --alert
sudo kerno watch fd --threshold 5 --interval 10s
```

**Watch TCP** runs an event reader goroutine + a ticker goroutine:
```
Event goroutine:
  FOR each event from BPF loader:
    Aggregate into map[4-tuple+comm] → {RTTs[], retransmit_count}

Ticker goroutine (every --interval):
  Snapshot the map
  Compute RTT percentiles (sorted-slice algorithm)
  Apply filters (--retransmits, --threshold-rtt)
  Render summary table
  Reset the map
```

**Watch OOM** is event-driven (no interval) since OOM kills are rare but critical:
```
FOR each OOM event from BPF loader:
    Apply --threshold filter on OOM score
    Print immediately (with --alert banner if enabled)
```

**Watch FD** computes per-process growth rates:
```
Every --interval:
    growth_rate = (opens - closes) / interval_seconds
    Filter processes where growth_rate ≥ --threshold
    Render table sorted by growth rate
```

### 9.5 kerno start - Daemon Mode

```bash
sudo kerno start                     # Default: Prometheus on :9090
sudo kerno start --prometheus-addr :9091
sudo kerno start --dashboard         # Future: web UI
```

**Implementation:**
1. `requireRoot()` - eBPF needs privileges
2. Load BPF programs individually with graceful degradation:
   - For each enabled collector in config, try `Load()`
   - On failure → log warning, skip (don't crash)
   - Track loaded count
3. Start event drain goroutines (read and discard to prevent kernel ring buffer overflow)
4. Start HTTP server: `/healthz` (JSON status) + `/metrics` (placeholder for Phase 5)
5. Block on signal (`<-ctx.Done()`)
6. Graceful shutdown: HTTP server → BPF programs → log completion

### 9.6 kerno predict - Failure Prediction

```bash
sudo kerno predict                          # 3 snapshots, 10s interval
sudo kerno predict --snapshots 5 --interval 15s  # More accurate
```

Collects multiple signal snapshots over time, then runs `doctor.Predict()`:
```
[IMMINENT] File Descriptor Exhaustion
   Signal:      fd
   ETA:         ~4m
   Confidence:  82%
   Current:     29072 net FDs
   Trend:       +20.3 FDs/sec
   Limit:       65536 (ulimit)
   Fix:         → ls -la /proc/<pid>/fd | wc -l
                → lsof -p <pid> | grep -c ESTABLISHED
```

### 9.7 kerno explain - AI Error Explainer

```bash
# Pipe a log line
echo "kernel: TCP: out of memory -- consider tuning tcp_mem" | kerno explain

# Or pass as argument
kerno explain "BUG: unable to handle page fault for address"
```

Sends the error message to the configured LLM with a kernel-expert system prompt. Returns plain-English explanation with root cause and fix steps.

---

## 10. Layer 7 - Configuration

### 10.1 Config Struct and Defaults

```go
type Config struct {
    LogLevel    string             // "info"
    LogFormat   string             // "text"
    Collectors  CollectorsConfig   // Which collectors are enabled
    Doctor      DoctorConfig       // Duration + thresholds
    AI          AIConfig           // Provider, model, API key, privacy
    Prometheus  PrometheusConfig   // Enabled, addr (:9090)
    Dashboard   DashboardConfig    // Enabled, addr (:8080)
    Kubernetes  KubernetesConfig   // Enabled, kubeconfig path
}
```

**Key defaults:**

| Setting | Default | Description |
|---------|---------|-------------|
| `doctor.duration` | 30s | How long doctor collects signals |
| `doctor.thresholds.syscall_p99_warning_ns` | 100ms | Syscall P99 warning threshold |
| `doctor.thresholds.syscall_p99_critical_ns` | 500ms | Syscall P99 critical threshold |
| `doctor.thresholds.tcp_retransmit_pct` | 2.0% | TCP retransmit rate threshold |
| `doctor.thresholds.oom_memory_pct` | 90.0% | Memory usage warning threshold |
| `doctor.thresholds.disk_p99_warning_ns` | 50ms | Disk latency warning |
| `doctor.thresholds.disk_p99_critical_ns` | 200ms | Disk latency critical |
| `doctor.thresholds.sched_delay_warning_ns` | 5ms | Scheduler delay warning |
| `doctor.thresholds.sched_delay_critical_ns` | 20ms | Scheduler delay critical |
| `doctor.thresholds.fd_growth_per_sec` | 10.0 | FD growth rate threshold |
| `ai.enabled` | false | AI is off by default |
| `ai.provider` | "anthropic" | Default LLM provider |
| `ai.privacy_mode` | "summary" | Only send aggregated data |

### 10.2 Precedence: Flags > Env > File > Defaults

```
1. CLI flag:     --log-level debug          ← Highest priority
2. Env var:      KERNO_LOG_LEVEL=debug
3. Config file:  log_level: debug
4. Default:      "info"                     ← Lowest priority
```

Config file search path:
1. `--config <path>` (explicit)
2. `/etc/kerno/config.yaml`
3. `~/.kerno/config.yaml`
4. `./config.yaml`

### 10.3 Validation

`Config.Validate()` checks:
- Log level is one of: debug, info, warn, error
- Log format is one of: text, json
- Doctor duration is between 1s and 5m
- If AI enabled: provider is valid, API key is present (except Ollama)
- If Prometheus enabled: address is not empty
- If Dashboard enabled: address is not empty

Fails fast with descriptive errors on startup.

---

## 11. How It All Connects: Data Flow

Here's a complete trace of what happens when you run `sudo kerno doctor`:

```
1. main.go → cli.New().Execute()
   └── cobra parses "doctor" command

2. root.PersistentPreRunE → initConfig()
   ├── Viper loads config.yaml
   ├── Binds KERNO_* env vars
   ├── Unmarshals to Config struct
   ├── Validates
   └── Initializes slog logger

3. doctor.RunE → runDoctor()
   ├── Resolve duration (flag → config → 30s)
   ├── Resolve AI enabled/disabled
   ├── Build AI analyzer (if enabled)
   │   ├── NewProvider("anthropic") → AnthropicProvider
   │   ├── NewRateLimitedProvider(provider, 10/min)
   │   ├── NewCache(5m TTL)
   │   └── NewAnalyzer(provider, cache, "summary")
   ├── NewEngine(thresholds, analyzer, logger)
   └── NewRegistry(logger) → registry

4. runDiagnosticCycle()
   ├── Create timeout context (30s)
   ├── Print "Collecting kernel signals for 30s..."
   ├── Wait for timeout
   ├── registry.Signals(30s) → *Signals
   │   └── (Currently returns empty signals → Phase 2 live collectors pending)
   │
   ├── engine.Diagnose(ctx, signals)
   │   ├── Phase 1: Evaluate(signals, thresholds)
   │   │   ├── evalDiskIOBottleneck() → []Finding
   │   │   ├── evalOOMKillOccurred() → []Finding
   │   │   ├── evalTCPRetransmitStorm() → []Finding
   │   │   ├── ... (all 9 rules)
   │   │   ├── evalHealthySystem() (if no findings)
   │   │   └── RankFindings(findings)
   │   │
   │   ├── Phase 2: analyzer.Analyze() (if AI enabled + actionable findings)
   │   │   ├── Check cache → miss
   │   │   ├── BuildUserPrompt(signals, findings, history, "summary")
   │   │   ├── provider.Complete(systemPrompt, userPrompt)
   │   │   │   └── HTTP POST to api.anthropic.com → JSON response
   │   │   ├── parseAnalysisResponse() → AnalysisResponse
   │   │   └── Cache result
   │   │
   │   ├── Phase 3: Build Report struct
   │   └── Phase 4: Append to history ring buffer
   │
   ├── renderer.Render(os.Stdout, report)
   │   └── PrettyRenderer: header → findings → AI analysis → actions → summary
   │
   └── If --exit-code && report.HasCritical() → exit 1
```

---

## 12. Build System

| Command | What it does |
|---------|-------------|
| `make build` | `go build` with version ldflags → `bin/kerno` |
| `make test` | `go test ./...` with timeout |
| `make test-race` | Tests with race detector |
| `make test-cover` | Coverage report → `coverage.html` |
| `make lint` | `golangci-lint` with strict config |
| `make vet` | `go vet ./...` |
| `make check` | vet + test + lint (full CI) |
| `make bpf` | Compile eBPF C → `.o` files (requires clang) |
| `make generate` | Run bpf2go code generation |
| `make docker` | Multi-stage Docker build |
| `make clean` | Remove all artifacts |

**Version injection:**
```makefile
LDFLAGS = -X github.com/optiqor/kerno/internal/version.Version=$(VERSION)
          -X github.com/optiqor/kerno/internal/version.Commit=$(COMMIT)
          -X github.com/optiqor/kerno/internal/version.Date=$(DATE)
```

---

## 13. Testing Strategy

| Package | Tests | What they cover |
|---------|-------|----------------|
| `internal/bpf` | 22 tests | Binary serialization round-trips for all 7 event types, string conversions, IP parsing |
| `internal/collector` | 8 tests | Registry register/start/stop, duplicate prevention, Signals aggregation |
| `internal/doctor` | 23+ tests | All 11 rules (positive + negative cases), ETA calculations, ranking algorithm, Pretty + JSON renderers |
| `internal/cli` | 21 tests | Filter functions, format helpers, percentile computation, TCP aggregation, FD growth rate, JSON output |
| `internal/config` | Tests | Default values, validation rules, error cases |
| `internal/version` | Tests | Version string formatting |

**Testing patterns:**
- **Table-driven tests** everywhere (Go convention)
- **Mock signals** → inject into rules → verify findings
- **Pure functions** for filtering/formatting → test without BPF
- **Binary round-trips** → serialize Go struct → deserialize → compare (ensures C/Go struct match)
- **No root required** for any test (BPF stubs return errors gracefully)

---

## 14. Design Principles

1. **Ship `kerno doctor` first.** Everything exists to support the diagnostic report.

2. **Deterministic before AI.** The rule engine always works. AI is frosting on the cake.

3. **Graceful degradation everywhere:**
   - AI unreachable → warn and continue
   - BPF program fails to load → skip, log, continue
   - Config file missing → use defaults
   - Not running as root → clear error message

4. **One Signals struct.** A single integration point for all consumers (doctor, exporters, dashboard, AI).

5. **No SDKs.** AI providers use raw HTTP. This prevents version conflicts, reduces binary size, and gives full control over request/response handling.

6. **Interfaces at the consumer.** `doctor.Analyzer` is defined in the doctor package (not ai), `collector.Collector` is in collector (not bpf). This follows the Go principle: "Accept interfaces, return structs."

7. **Production-grade from day one.** Structured logging (`log/slog`), error wrapping (`fmt.Errorf("context: %w", err)`), graceful shutdown, configurable thresholds.

8. **Linux-first, Kubernetes-optional.** Every feature works on a bare VM. K8s enrichment is an additive layer (Phase 6).

---

## 15. Glossary

| Term | Definition |
|------|-----------|
| **eBPF** | Extended Berkeley Packet Filter - kernel-level programmability framework |
| **CO-RE** | Compile Once, Run Everywhere - eBPF portability via BTF |
| **BTF** | BPF Type Format - kernel type metadata for CO-RE |
| **vmlinux.h** | Auto-generated header containing all kernel type definitions |
| **bpf2go** | cilium/ebpf tool that compiles C to eBPF bytecode and generates Go bindings |
| **Ring buffer** | Lock-free kernel→userspace event queue (BPF_MAP_TYPE_RINGBUF) |
| **Tracepoint** | Stable kernel hook point with defined ABI (preferred) |
| **Kprobe** | Dynamic hook on any kernel function (less stable, more flexible) |
| **P99** | 99th percentile - the value below which 99% of observations fall |
| **RTT** | Round-Trip Time - time for a TCP packet to go and come back |
| **OOM** | Out of Memory - kernel kills a process to free memory |
| **Run queue delay** | Time a process waits on the CPU queue before being scheduled |
| **FD** | File Descriptor - integer handle for an open file/socket/pipe |
| **ulimit** | Per-process resource limit (FD limit is typically 65536) |
| **NDJSON** | Newline-delimited JSON - one JSON object per line |
| **Signals** | Kerno's unified snapshot struct containing all 7 signal dimensions |
| **Finding** | A diagnostic conclusion from a rule evaluation |
| **Severity** | INFO (normal), WARNING (investigate), CRITICAL (act now) |
