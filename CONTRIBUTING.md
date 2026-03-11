# Contributing to Kerno

Thank you for your interest in contributing to Kerno! This document provides guidelines, full setup instructions, and best practices for contributors.

## Table of Contents

- [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
- [Development Environment Setup](#development-environment-setup)
- [Building from Source](#building-from-source)
- [Running Tests](#running-tests)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Commit Message Convention](#commit-message-convention)
- [Code Style](#code-style)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)
- [License](#license)

---

## Developer Certificate of Origin (DCO)

All contributions to Kerno must be signed off under the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This certifies that you wrote or have the right to submit the code you are contributing.

**Every commit must include a `Signed-off-by` line:**

```
Signed-off-by: Your Name <your.email@example.com>
```

You can do this automatically by committing with the `-s` flag:

```bash
git commit -s -m "feat: add syscall latency collector"
```

---

## Development Environment Setup

### System Requirements

| Requirement | Minimum | Recommended | Notes |
|---|---|---|---|
| **Linux kernel** | 5.8 | 6.1+ | Must have `CONFIG_DEBUG_INFO_BTF=y` |
| **Go** | 1.24 | 1.25+ | [install](https://go.dev/doc/install) |
| **clang** | 14 | 17+ | For eBPF C compilation |
| **llvm** | 14 | 17+ | `llvm-strip` used by bpf2go |
| **libbpf-dev** | 0.8 | 1.0+ | BPF CO-RE headers |
| **bpftool** | — | latest | BTF inspection and debugging |
| **make** | 4.0 | — | Build orchestration |

### Step 1 — Install System Dependencies

**Ubuntu / Debian (22.04+):**

```bash
sudo apt-get update
sudo apt-get install -y \
  clang llvm llvm-dev \
  libbpf-dev \
  linux-headers-$(uname -r) \
  linux-tools-$(uname -r) linux-tools-common \
  make gcc pkg-config \
  git curl
```

**Fedora (38+):**

```bash
sudo dnf install -y \
  clang llvm llvm-devel \
  libbpf-devel \
  kernel-headers kernel-devel \
  bpftool \
  make gcc pkg-config \
  git curl
```

**Arch Linux:**

```bash
sudo pacman -S \
  clang llvm \
  libbpf \
  linux-headers \
  bpf \
  make gcc pkg-config \
  git curl
```

### Step 2 — Install Go

If you don't have Go 1.24+ installed:

```bash
# Download (adjust version as needed)
curl -fsSL https://go.dev/dl/go1.25.4.linux-amd64.tar.gz -o /tmp/go.tar.gz

# Install
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tar.gz

# Add to PATH (add to ~/.bashrc or ~/.zshrc for persistence)
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Verify
go version
```

### Step 3 — Install Go Tooling

```bash
# Install development tools used by the Makefile
make install-tools
```

This installs:

| Tool | Purpose |
|---|---|
| `bpf2go` | Generate Go bindings from eBPF C programs |
| `golangci-lint` | Aggregated linter (80+ checks) |
| `goreleaser` | Cross-compile and release binaries |

Or install manually:

```bash
go install github.com/cilium/ebpf/cmd/bpf2go@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install github.com/goreleaser/goreleaser/v2@latest
```

### Step 4 — Verify BTF Support

Kerno requires BTF (BPF Type Format) in your kernel:

```bash
# Check if BTF is available
ls /sys/kernel/btf/vmlinux && echo "BTF: OK" || echo "BTF: MISSING"

# Alternative check
bpftool btf dump file /sys/kernel/btf/vmlinux format raw | head -c 4
```

If BTF is missing, you need a kernel compiled with `CONFIG_DEBUG_INFO_BTF=y`. Most modern distro kernels (Ubuntu 22.04+, Fedora 38+, Arch) have this enabled by default.

### Step 5 — Clone and Build

```bash
git clone https://github.com/lowplane/kerno.git
cd kerno

# Standard build (uses stub BPF types — no clang required)
make build

# Verify the binary works
./bin/kerno version
./bin/kerno --help
```

### Step 6 — Full Build with eBPF Compilation (Optional)

If you're working on the eBPF C programs:

```bash
# Compile eBPF programs + generate Go bindings + build binary
make build-ebpf

# Or just compile the eBPF programs
make bpf

# Or just regenerate Go bindings
make generate
```

> **Note:** The standard `make build` uses pre-generated Go stub types (`gen_stub.go`) so you can develop and test Go code without clang/libbpf installed. Only use `make build-ebpf` when modifying the eBPF C programs.

### Step 7 — Run the Doctor (requires root)

```bash
sudo ./bin/kerno doctor
sudo ./bin/kerno doctor --duration 10s
sudo ./bin/kerno doctor --output json
```

---

## Building from Source

### Make Targets

| Target | Description | Requires Root | Requires clang |
|---|---|:---:|:---:|
| `make build` | Build binary (stub BPF) | No | No |
| `make build-ebpf` | Full build with eBPF compilation | No | **Yes** |
| `make build-debug` | Build without symbol stripping | No | No |
| `make bpf` | Compile eBPF C → `.o` files | No | **Yes** |
| `make generate` | Run `bpf2go` to generate Go types | No | **Yes** |
| `make test` | Run unit tests | No | No |
| `make test-race` | Run tests with race detector | No | No |
| `make test-cover` | Generate HTML coverage report | No | No |
| `make lint` | Run golangci-lint | No | No |
| `make vet` | Run `go vet` | No | No |
| `make fmt` | Format Go source files | No | No |
| `make check` | Run lint + test + vet (CI equivalent) | No | No |
| `make docker` | Build Docker image | No | No |
| `make clean` | Remove build artifacts | No | No |
| `make install-tools` | Install Go dev tools | No | No |
| `make help` | Show all targets with descriptions | No | No |

### Build Flags

The Makefile injects version metadata via `-ldflags`:

```bash
# Version comes from git describe or latest tag
# Commit comes from HEAD
# Date comes from build time
./bin/kerno version
# → kerno v0.1.0 (commit: abc1234, built: 2026-03-11T12:00:00Z, go1.25.4, linux/amd64)
```

### Docker Build

```bash
# Build multi-stage image (compiles inside container)
make docker

# Run with required privileges
docker run --privileged --pid=host \
  ghcr.io/lowplane/kerno:latest doctor
```

---

## Running Tests

```bash
# Unit tests (no root, no eBPF)
make test

# With race detector (slower, catches data races)
make test-race

# With HTML coverage report (opens coverage.html)
make test-cover

# Run a specific package
go test ./internal/config/... -v

# Run a specific test
go test ./internal/bpf/... -run TestSyscallEventBinaryRoundTrip -v

# Full CI check (lint + vet + test)
make check
```

**Test categories:**

- `internal/version` — Build metadata resolution tests
- `internal/config` — Configuration parsing + validation (8 table-driven tests)
- `internal/bpf` — Event binary round-trip, helper methods, type consistency
- `internal/collector` — Registry lifecycle, signal aggregation

---

## Project Structure

```
kerno/
├── cmd/kerno/                  # Binary entry point
│   └── main.go
├── internal/
│   ├── bpf/                    # eBPF loaders + Go event types
│   │   ├── c/                  # eBPF C source files
│   │   │   ├── headers/        #   vmlinux.h + kerno.h (shared structs)
│   │   │   ├── syscall_latency.c
│   │   │   ├── tcp_monitor.c
│   │   │   ├── oom_track.c
│   │   │   ├── disk_io.c
│   │   │   ├── sched_delay.c
│   │   │   └── fd_track.c
│   │   ├── loader.go           # Loader interface + LoaderSet
│   │   ├── events.go           # Go event structs (mirror C structs)
│   │   ├── gen_stub.go         # Stub types for dev builds (no clang)
│   │   ├── syscall_latency.go  # Typed loader for syscall program
│   │   ├── tcp_monitor.go      # Typed loader for TCP program
│   │   ├── oom_track.go        # Typed loader for OOM program
│   │   ├── disk_io.go          # Typed loader for disk I/O program
│   │   ├── sched_delay.go      # Typed loader for sched program
│   │   └── fd_track.go         # Typed loader for FD program
│   ├── cli/                    # Cobra CLI commands
│   │   ├── root.go             #   Root command, flags, logger init
│   │   ├── doctor.go           #   `kerno doctor` command
│   │   ├── version.go          #   `kerno version` command
│   │   └── start.go            #   `kerno start` daemon command
│   ├── collector/              # Signal collection + aggregation
│   │   ├── collector.go        #   Collector interface + Registry
│   │   └── signals.go          #   Typed signal snapshots
│   ├── config/                 # Typed configuration
│   │   └── config.go           #   Config struct, defaults, validation
│   └── version/                # Build metadata
│       └── version.go          #   Version, commit, date via ldflags
├── .github/
│   ├── workflows/
│   │   ├── ci.yml              # Lint, test, build, BPF, Docker jobs
│   │   └── release.yml         # GoReleaser on tag push
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── PULL_REQUEST_TEMPLATE.md
├── Makefile                    # Build orchestration (20+ targets)
├── Dockerfile                  # Multi-stage build (golang → distroless)
├── Dockerfile.goreleaser       # Minimal runtime for goreleaser
├── .golangci.yml               # Linter configuration (v2 format)
├── .goreleaser.yml             # Release automation
├── .editorconfig               # Editor settings
├── go.mod / go.sum             # Go module definition
├── README.md                   # Project overview
├── LICENSE                     # Apache 2.0
├── SECURITY.md                 # Vulnerability disclosure policy
├── GOVERNANCE.md               # Project governance
└── CODE_OF_CONDUCT.md          # Contributor covenant
```

### Key Architecture Decisions

- **`internal/`** — All packages are internal; the only public API is the CLI binary.
- **Build tag strategy** — `gen_stub.go` (`//go:build !ebpf`) provides stub types so `make build` works without clang. The real BPF-generated types are only produced when running `make generate` with the `ebpf` build tag.
- **Loader interface** — Each eBPF program has a typed Go loader implementing a common `Loader` interface, enabling uniform lifecycle management via `LoaderSet`.
- **Collector interface** — Collectors consume raw events from loaders, aggregate them into typed snapshots, and expose them via a `Registry` for the doctor engine.

---

## Development Workflow

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-user>/kerno.git
   cd kerno
   ```
3. **Add upstream remote:**
   ```bash
   git remote add upstream https://github.com/lowplane/kerno.git
   ```
4. **Create a branch** from `main`:
   ```bash
   git fetch upstream
   git checkout -b feat/my-feature upstream/main
   ```
5. **Make your changes** following the code style guidelines below.
6. **Write tests** for your changes.
7. **Run the full check suite:**
   ```bash
   make check  # lint + test + vet
   ```
8. **Commit** with DCO sign-off:
   ```bash
   git commit -s -m "feat: description of change"
   ```
9. **Push** to your fork and open a Pull Request:
   ```bash
   git push origin feat/my-feature
   ```

### Common Development Tasks

```bash
# Adding a new eBPF program:
# 1. Create C source in internal/bpf/c/
# 2. Create Go loader in internal/bpf/
# 3. Add stub types in gen_stub.go
# 4. Register in LoaderSet
# 5. Run: make build-ebpf && make test

# Adding a new CLI command:
# 1. Create command file in internal/cli/
# 2. Register as subcommand of root
# 3. Run: make build && ./bin/kerno <command> --help

# Adding a new collector:
# 1. Implement the Collector interface
# 2. Add snapshot type in signals.go
# 3. Register in the Registry
# 4. Write tests
# 5. Run: make check
```

---

## Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
Signed-off-by: Name <email>
```

**Types:**

| Type | Description |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting, no code change |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `test` | Adding or correcting tests |
| `build` | Build system or external dependency changes |
| `ci` | CI configuration changes |
| `chore` | Other changes that don't modify src or test files |

**Scopes:** `bpf`, `collector`, `doctor`, `cli`, `export`, `dashboard`, `adapter`, `config`, `helm`

**Examples:**

```
feat(doctor): add OOM countdown rule with ETA calculation
fix(bpf): handle verifier rejection on kernel 5.8
docs: update quickstart guide for ARM64
perf(collector): reduce syscall aggregation allocations by 40%
```

---

## Code Style

### Go

- Follow [Effective Go](https://go.dev/doc/effective_go) and the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).
- All exported types, functions, and methods **must** have doc comments.
- Use `log/slog` for structured logging — never `fmt.Println` in library code.
- Error messages are lowercase, no trailing punctuation: `return fmt.Errorf("loading BPF program: %w", err)`.
- Wrap errors with `%w` for the entire call chain.
- Use `context.Context` as the first parameter for anything cancellable.
- Table-driven tests with `t.Run` subtests.

### eBPF (C)

- Include `vmlinux.h` first, then `<bpf/bpf_helpers.h>`, then `kerno.h`.
- Use CO-RE (`BPF_CORE_READ`) for all field access.
- Prefer tracepoints over kprobes where available.
- Keep programs small — the verifier has limits.
- Comment non-obvious kernel interactions.
- All shared structs go in `internal/bpf/c/headers/kerno.h` — the Go event types in `events.go` must match exactly.

### General

- `make lint` must pass with zero warnings.
- No `TODO` comments in merged code unless tracking a filed issue (`// TODO(#123): ...`).
- All new features require tests.
- All new CLI commands require documentation.

---

## Pull Request Guidelines

- PRs should be focused — one concern per PR.
- Include a clear description of **what** and **why**.
- Link related issues with `Fixes #123` or `Relates to #123`.
- All CI checks must pass.
- At least one maintainer approval is required.
- Squash-merge is preferred for clean history.

## Reporting Issues

- Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) for bugs.
- Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md) for features.
- Include kernel version (`uname -r`), Go version, and kerno version.
- For eBPF verifier errors, include the full verifier log.

## Security Vulnerabilities

**Do not file public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## License

By contributing to Kerno, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
