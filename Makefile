# Copyright 2026 Optiqor contributors
# SPDX-License-Identifier: Apache-2.0

# ─── Project Metadata ────────────────────────────────────────────────────────

MODULE   := github.com/optiqor/kerno
BIN_NAME := kerno
BIN_DIR  := bin

# Build metadata (injected via -ldflags).
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE     ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

# ─── Go Tool Configuration ───────────────────────────────────────────────────

GO       := go
GOFLAGS  := -trimpath
GOTAGS   :=

# eBPF toolchain.
CLANG    ?= clang
LLC      ?= llc
BPFTOOL  ?= bpftool
BPF_CFLAGS := -O2 -g -Wall -Werror \
	-target bpf \
	-D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
	-I internal/bpf/c/headers

# Lint.
GOLANGCI_LINT_VERSION := v2.1.6
GOLANGCI_LINT := $(shell command -v golangci-lint 2>/dev/null)

# ─── Dashboard UI ────────────────────────────────────────────────────────────

KERNO_UI_VERSION ?= latest
UI_DIST_DIR      := internal/dashboard/dist/assets

# ─── Phony Targets ───────────────────────────────────────────────────────────

.PHONY: all build build-ebpf build-debug test test-cover test-race lint vet check \
	fmt clean bpf generate docker help \
	ui-fetch ui-dev install-tools setup precommit \
	verify demo demo-cast bpf-verify

.DEFAULT_GOAL := help

# ─── Build ───────────────────────────────────────────────────────────────────

## build: Compile the kerno binary (production, uses stub BPF if not generated)
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "$(GOTAGS)" -ldflags "$(LDFLAGS)" \
		-o $(BIN_DIR)/$(BIN_NAME) ./cmd/kerno/
	@echo "Built $(BIN_DIR)/$(BIN_NAME) ($(VERSION))"

## build-ebpf: Full build with eBPF code generation (requires clang + libbpf)
build-ebpf: generate
	@$(MAKE) build GOTAGS=ebpf

## build-debug: Compile with debug symbols (for dlv)
build-debug:
	@mkdir -p $(BIN_DIR)
	$(GO) build -gcflags "all=-N -l" -o $(BIN_DIR)/$(BIN_NAME)-debug ./cmd/kerno/
	@echo "Built $(BIN_DIR)/$(BIN_NAME)-debug (debug symbols)"

## all: Full build pipeline (generate + build + test + lint)
all: check build

# ─── eBPF ────────────────────────────────────────────────────────────────────

## bpf: Compile all eBPF C programs to .o object files
bpf:
	@echo "Compiling eBPF programs..."
	@for src in internal/bpf/c/*.c; do \
		[ -f "$$src" ] || continue; \
		obj=$$(echo "$$src" | sed 's/\.c$$/_bpfel.o/'); \
		echo "  CC $$src -> $$obj"; \
		$(CLANG) $(BPF_CFLAGS) -c "$$src" -o "$$obj"; \
	done
	@echo "eBPF compilation complete."

## generate: Run go generate (bpf2go code generation)
##
## After bpf2go runs we rewrite the build tag on each generated *_bpfel.go
## so they only compile when the `ebpf` tag is set. Without this step,
## the generated files and the gen_stub.go fallback would both compile on
## amd64/arm64 and cause duplicate-declaration errors.
generate:
	@if ls internal/bpf/c/*.c 1>/dev/null 2>&1; then \
		echo "Running go generate..."; \
		$(GO) generate ./internal/bpf/...; \
		echo "Gating generated files behind '-tags ebpf'..."; \
		for f in internal/bpf/*_bpfel.go internal/bpf/*_bpfeb.go; do \
			[ -f "$$f" ] || continue; \
			sed -i.bak -E 's|^//go:build ([^ ].*)$$|//go:build ebpf \&\& (\1)|' "$$f"; \
			rm -f "$$f.bak"; \
		done; \
	fi

# ─── Quality ─────────────────────────────────────────────────────────────────

## test: Run all unit tests
test:
	$(GO) test ./... -count=1 -timeout 60s

## test-race: Run tests with race detector
test-race:
	$(GO) test ./... -count=1 -race -timeout 120s

## test-cover: Run tests with coverage report
test-cover:
	$(GO) test ./... -count=1 -coverprofile=coverage.txt -covermode=atomic -timeout 120s
	$(GO) tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run golangci-lint
lint:
ifdef GOLANGCI_LINT
	$(GOLANGCI_LINT) run ./...
else
	@echo "golangci-lint not found. Install with: make install-tools"
	@exit 1
endif

## vet: Run go vet
vet:
	$(GO) vet ./...

## fmt: Format all Go source files
fmt:
	@gofmt -s -w .
	@echo "Formatted."

## check: Run vet + test + lint (full CI check)
check: vet test lint

# ─── Dashboard ───────────────────────────────────────────────────────────────

## ui-fetch: Download kerno-ui dist from GitHub Releases
ui-fetch:
	@mkdir -p $(UI_DIST_DIR)
	@if [ -d "$(UI_DIST_DIR)" ] && [ "$$(ls -A $(UI_DIST_DIR))" ]; then \
		echo "UI assets already present. Run 'make clean' to refetch."; \
	else \
		echo "Fetching kerno-ui $(KERNO_UI_VERSION)..."; \
		echo "  TODO: Download from https://github.com/optiqor/kerno-ui/releases"; \
		echo "  For now, the dashboard will show a 'no assets found' message."; \
	fi

## ui-dev: Start kerno API server with CORS for local frontend development
ui-dev: build
	$(BIN_DIR)/$(BIN_NAME) start --dashboard --log-level debug

# ─── Docker ──────────────────────────────────────────────────────────────────

## docker: Build Docker image
docker:
	docker build -t ghcr.io/optiqor/kerno:$(VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		.

# ─── Utilities ───────────────────────────────────────────────────────────────

## install-tools: Install Go-based development tools (golangci-lint, bpf2go)
install-tools:
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@echo "Installing bpf2go..."
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest
	@echo "Done. Ensure $$GOPATH/bin is in your PATH."

## setup: One-shot dev environment install (system pkgs + Go tools + git hooks)
#
# Installs everything a contributor needs to build, test, and submit
# a PR — clang/llvm/libbpf-dev (apt or dnf), Go tools, and pre-commit
# hooks. Idempotent; safe to re-run.
setup:
	@echo "==> Detecting OS and package manager..."
	@if command -v apt-get >/dev/null; then \
		echo "==> Installing system packages via apt-get..."; \
		sudo apt-get update; \
		sudo apt-get install -y --no-install-recommends \
			clang llvm libbpf-dev linux-headers-generic linux-tools-common \
			bpftool jq make git ca-certificates; \
	elif command -v dnf >/dev/null; then \
		echo "==> Installing system packages via dnf..."; \
		sudo dnf install -y \
			clang llvm libbpf-devel kernel-devel bpftool jq make git ca-certificates; \
	elif command -v pacman >/dev/null; then \
		echo "==> Installing system packages via pacman..."; \
		sudo pacman -S --needed --noconfirm \
			clang llvm libbpf bpf jq make git; \
	else \
		echo "Unsupported package manager. Install manually:"; \
		echo "  clang, llvm, libbpf-dev, bpftool, jq, make"; \
		exit 1; \
	fi
	@echo ""
	@echo "==> Installing Go tools..."
	@$(MAKE) install-tools
	@echo ""
	@echo "==> Installing pre-commit hooks (optional)..."
	@if command -v pre-commit >/dev/null; then \
		pre-commit install --install-hooks --hook-type commit-msg --hook-type pre-commit; \
		echo "    pre-commit hooks installed."; \
	else \
		echo "    pre-commit not installed — skipping."; \
		echo "    Install with: pip install pre-commit && make precommit"; \
	fi
	@echo ""
	@echo "==> Verifying toolchain..."
	@command -v clang   >/dev/null && echo "    [OK] clang:   $$(clang --version | head -1)"
	@command -v bpftool >/dev/null && echo "    [OK] bpftool: $$(bpftool version | head -1)"
	@command -v go      >/dev/null && echo "    [OK] go:      $$(go version)"
	@command -v golangci-lint >/dev/null && echo "    [OK] golangci-lint: $$(golangci-lint --version | head -1)"
	@test -f /sys/kernel/btf/vmlinux && echo "    [OK] BTF available at /sys/kernel/btf/vmlinux" \
		|| echo "    [WARN] /sys/kernel/btf/vmlinux missing — BPF may not load on this host"
	@echo ""
	@echo "==> Setup complete. Try: make build && make test"

## precommit: Install pre-commit hooks (requires pip-installed pre-commit)
precommit:
	@if ! command -v pre-commit >/dev/null; then \
		echo "Install pre-commit first: pip install pre-commit"; \
		exit 1; \
	fi
	pre-commit install --install-hooks --hook-type commit-msg --hook-type pre-commit
	@echo "Hooks installed. They run on every git commit."
	@echo "To run all hooks now: pre-commit run --all-files"

## bpf-verify: Build the standalone BPF verifier load harness
bpf-verify:
	$(GO) build -o $(BIN_DIR)/bpf-verify ./cmd/bpf-verify
	@echo "Built $(BIN_DIR)/bpf-verify (run with sudo)"

## verify: Run the comprehensive 14-phase production-readiness check
verify: build-ebpf bpf-verify
	@./scripts/verify.sh

## demo: Record demo.gif via vhs (https://github.com/charmbracelet/vhs)
##
## Strategy: grant bin/kerno the BPF capabilities via `setcap` so it
## doesn't need sudo. vhs then runs as the regular user — sudo'd vhs
## tends to fail because it loses the graphical/session env. The caps
## are scoped to ./bin/kerno only and are wiped on rebuild, so this
## is no riskier than `sudo kerno doctor`.
##
## We resolve vhs from $PATH first, then $(go env GOBIN), then
## $HOME/go/bin — Go-installed binaries often aren't on PATH inside
## make's stripped environment.
demo: build-ebpf bpf-verify
	@VHS=$$(command -v vhs 2>/dev/null); \
	if [ -z "$$VHS" ]; then VHS=$$(go env GOBIN 2>/dev/null)/vhs; fi; \
	if [ ! -x "$$VHS" ]; then VHS="$$HOME/go/bin/vhs"; fi; \
	if [ ! -x "$$VHS" ]; then \
		echo "vhs not found. Install with:"; \
		echo "  sudo apt-get install -y ttyd ffmpeg"; \
		echo "  go install github.com/charmbracelet/vhs@latest"; \
		echo "  # then either:"; \
		echo "  #   export PATH=\"\$$HOME/go/bin:\$$PATH\"      (persistent)"; \
		echo "  #   or re-run 'make demo' (it now auto-finds \$$HOME/go/bin)"; \
		exit 1; \
	fi; \
	echo "==> Using vhs at $$VHS"; \
	echo "==> Granting BPF capabilities to bin/kerno (sudo password may be required)"; \
	sudo setcap 'cap_bpf,cap_perfmon,cap_sys_ptrace,cap_sys_admin,cap_net_admin,cap_dac_read_search+ep' ./bin/kerno; \
	echo "==> Recording demo.gif (no further sudo needed; vhs runs as $$USER)"; \
	"$$VHS" demo.tape
	@echo "Wrote demo.gif ($$(du -h demo.gif | cut -f1))"
	@if command -v gifsicle >/dev/null; then \
		gifsicle --optimize=3 demo.gif -o demo.gif && \
		echo "Optimized demo.gif → $$(du -h demo.gif | cut -f1)"; \
	else \
		echo "Tip: install gifsicle for smaller GIFs (apt install gifsicle)"; \
	fi

## demo-cast: Record an asciinema cast (alternative to vhs)
demo-cast: build-ebpf bpf-verify
	@if ! command -v asciinema >/dev/null; then \
		echo "asciinema not installed: apt install asciinema"; \
		exit 1; \
	fi
	asciinema rec --title "kerno doctor — eBPF incident diagnosis" \
		--idle-time-limit 2 --command "scripts/demo.sh" demo.cast
	@echo "Wrote demo.cast"

## clean: Remove build artifacts
clean:
	rm -rf $(BIN_DIR) coverage.txt coverage.html
	rm -rf $(UI_DIST_DIR)
	rm -f internal/bpf/*_bpfel.o internal/bpf/*_bpfeb.o
	rm -f internal/bpf/*_bpfel.go internal/bpf/*_bpfeb.go
	$(GO) clean -cache -testcache

# ─── Help ────────────────────────────────────────────────────────────────────

## help: Show this help message
help:
	@echo "Kerno — Kernel Observability Engine"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | \
		sed -E 's/^## //' | \
		awk -F: '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=$(VERSION)"
	@echo "  COMMIT=$(COMMIT)"
