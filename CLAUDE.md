# CLAUDE.md — Kerno Development Guide

> Instructions for Claude Code when working on this repository.

## Project Overview

Kerno is an eBPF-based kernel observability engine for Linux. It traces 6 kernel signal dimensions (syscall latency, TCP flows, OOM events, disk I/O, scheduler delays, FD leaks) and produces diagnostic reports via `kerno doctor`.

**Module:** `github.com/lowplane/kerno`
**Go version:** 1.25+
**License:** Apache 2.0

## Repository Layout

```
cmd/kerno/          → Binary entry point (main.go)
internal/
  ai/               → LLM provider abstraction (anthropic, openai, ollama)
  bpf/              → eBPF C programs + Go loaders (cilium/ebpf + bpf2go)
  bpf/c/            → eBPF C source files + headers (vmlinux.h, kerno.h)
  cli/              → Cobra CLI commands (root, doctor, explain, predict, start, version)
  collector/        → Signal collection interface, registry, Signals struct
  config/           → Viper-based typed configuration
  doctor/           → Diagnostic engine: rules, findings, renderers, predict
  version/          → Build metadata (injected via ldflags)
deploy/             → Kubernetes manifests + Helm chart (future)
.github/workflows/  → CI (lint, test, build, BPF compile) + Release (goreleaser)
```

## Build & Test

```bash
make build          # Compile binary (stub BPF, no clang needed)
make test           # Run unit tests
make test-race      # Run tests with race detector
make test-cover     # Generate coverage report
make lint           # golangci-lint
make vet            # go vet
make check          # Full CI check (vet + test + lint)
make bpf            # Compile eBPF C programs (requires clang + libbpf-dev)
make generate       # Run bpf2go code generation
make docker         # Build Docker image
make clean          # Remove build artifacts
```

Quick validation: `go build ./... && go test ./... && go vet ./...`

## Architecture Constraints

### AI Boundary (CRITICAL)
AI only touches the layer where eBPF data becomes human understanding.
- Kernel data collection stays pure eBPF + Go
- AI NEVER touches the hot path
- AI is a post-processing layer ONLY
- The deterministic doctor engine works independently of AI
- AI enriches findings — never replaces them

```
eBPF → Loaders → Collectors → Signals snapshot
                                    │
                              Rule Engine (deterministic, always runs)
                                    │
                                    ▼ []Finding
                              AI Analyzer (optional, post-processing)
                                    │
                                    ▼
                              Enhanced Doctor Report
```

### Signal Flow
All data flows through the `collector.Signals` struct — the single integration point consumed by doctor, exporters, and dashboard.

### Graceful Degradation
- AI enabled + reachable → full AI analysis
- AI enabled + unreachable → fallback template analysis + warning
- AI disabled → deterministic rule engine only (default)
- eBPF program fails to load → skip that collector, clear error, continue

## Code Conventions

### Go
- Use `log/slog` for structured logging (no third-party loggers)
- Errors: `fmt.Errorf("context: %w", err)` — always wrap with context
- No `panic` in library code. Return errors.
- Test files: `*_test.go` next to source, table-driven tests preferred
- Package names: short, lowercase, no underscores
- Interfaces in the consumer package (e.g., `doctor.Analyzer` not `ai.Analyzer`)

### eBPF (C)
- CO-RE (Compile Once, Run Everywhere) via vmlinux.h
- Prefer tracepoints over kprobes for stability
- Ring buffer for event delivery (requires kernel 5.8+)
- All event structs in `kerno.h` with packed attribute

### Config
- Viper precedence: CLI flags > env vars > config file > defaults
- Env prefix: `KERNO_` (e.g., `KERNO_LOG_LEVEL`, `KERNO_AI_API_KEY`)
- Config file search: `/etc/kerno/config.yaml`, `$HOME/.kerno/`, `.`

## Commit Convention

Use **Conventional Commits**:

```
feat(scope): short description     # New feature
fix(scope): short description      # Bug fix
docs(scope): short description     # Documentation
test(scope): short description     # Tests
refactor(scope): short description # Refactoring
build(scope): short description    # Build system
ci(scope): short description       # CI/CD
chore(scope): short description    # Maintenance
```

**Scopes:** `doctor`, `ai`, `cli`, `collector`, `bpf`, `config`, `export`, `k8s`, `dashboard`

Keep messages concise — one line, under 72 chars. Body only if needed for "why".

**IMPORTANT:** Do NOT add `Co-Authored-By` lines. All commits are authored solely by the repo owner.

**IMPORTANT:** Before every commit, run `go build ./... && go test ./... && go vet ./...` and ensure all pass. Never commit broken code.

## PR Strategy

- Small, focused PRs — one logical change per PR
- PR title matches conventional commit format
- All PRs go through CI (lint + test + build)
- DCO sign-off required on all commits (`git commit -s`)

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/cilium/ebpf` | eBPF loader + bpf2go codegen |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/spf13/viper` | Configuration management |

## What NOT to Do

- Don't add LLM SDK dependencies — all AI providers use raw `net/http`
- Don't log sensitive data (API keys, file contents, env vars)
- Don't use `panic` or `os.Exit` outside `main.go`
- Don't add features beyond the current phase scope
- Don't break the `go build ./... && go test ./...` invariant
- Don't commit generated files (`*_bpfel.go`, `*_bpfeb.go`) — CI generates them

## Testing

- Doctor rules: inject mock `collector.Signals` → verify `[]Finding` output
- Renderers: render to `bytes.Buffer` → verify string contains expected sections
- AI providers: `httptest.Server` for mock LLM responses
- Config: validate defaults, custom values, and error cases
- Target: ≥80% unit test coverage

## Current Phase Status

See TODO.md for the full roadmap. Key phases:
- Phase 0 (Skeleton): COMPLETE
- Phase 1 (eBPF scaffolding): COMPLETE
- Phase 2 (Collector types): COMPLETE
- Phase 3 (Doctor engine): COMPLETE
- Phase 4 (CLI): IN PROGRESS
- AI Integration: IN PROGRESS (providers + analyzer + explain done, predict scaffolded)
