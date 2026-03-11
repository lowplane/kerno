# Copyright 2026 Lowplane contributors
# SPDX-License-Identifier: Apache-2.0

# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.25-bookworm AS builder

# Install eBPF build dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Cache Go module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Copy source.
COPY . .

# Build arguments for version injection.
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# Build the binary.
RUN make build VERSION=${VERSION} COMMIT=${COMMIT} DATE=${DATE}

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
# distroless/static: no shell, no package manager, tiny attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="kerno" \
      org.opencontainers.image.description="eBPF-based kernel observability engine" \
      org.opencontainers.image.source="https://github.com/lowplane/kerno" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Lowplane"

COPY --from=builder /src/bin/kerno /usr/local/bin/kerno

# Kerno needs to run as root (or with CAP_BPF+CAP_PERFMON) to load eBPF.
# In Kubernetes, this is configured via securityContext in the DaemonSet.
USER root

# Prometheus metrics.
EXPOSE 9090
# Dashboard.
EXPOSE 8080

ENTRYPOINT ["kerno"]
CMD ["start"]
