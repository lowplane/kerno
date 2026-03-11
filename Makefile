# Copyright 2026 Lowplane contributors
# SPDX-License-Identifier: Apache-2.0

# ─── Project Metadata ────────────────────────────────────────────────────────

MODULE   := github.com/lowplane/kerno
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
	ui-fetch ui-dev install-tools

.DEFAULT_GOAL := help

# ─── Build ───────────────────────────────────────────────────────────────────

## build: Compile the kerno binary (production, uses stub BPF if not generated)
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "$(GOTAGS)" -ldflags "$(LDFLAGS)" \
		-o $(BIN_DIR)/$(BIN_NAME) ./cmd/kerno/
	@echo "Built $(BIN_DIR)/$(BIN_NAME) ($(VERSION))"

## build-ebpf: Full build with eBPF code generation (requires clang + libbpf)
build-ebpf: generate build

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
generate:
	@if ls internal/bpf/c/*.c 1>/dev/null 2>&1; then \
		echo "Running go generate..."; \
		$(GO) generate ./internal/bpf/...; \
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
		echo "  TODO: Download from https://github.com/lowplane/kerno-ui/releases"; \
		echo "  For now, the dashboard will show a 'no assets found' message."; \
	fi

## ui-dev: Start kerno API server with CORS for local frontend development
ui-dev: build
	$(BIN_DIR)/$(BIN_NAME) start --dashboard --log-level debug

# ─── Docker ──────────────────────────────────────────────────────────────────

## docker: Build Docker image
docker:
	docker build -t ghcr.io/lowplane/kerno:$(VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		.

# ─── Utilities ───────────────────────────────────────────────────────────────

## install-tools: Install development tools
install-tools:
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@echo "Done. Ensure $$GOPATH/bin is in your PATH."

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
