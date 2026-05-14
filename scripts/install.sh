#!/usr/bin/env bash
# Copyright 2026 Optiqor contributors
# SPDX-License-Identifier: Apache-2.0
#
# Kerno installer — works on any Linux with kernel >= 5.8 and BTF.
#
# Usage:
#   curl -sfL https://raw.githubusercontent.com/optiqor/kerno/main/scripts/install.sh | bash
#   curl -sfL https://raw.githubusercontent.com/optiqor/kerno/main/scripts/install.sh | bash -s -- --version v0.2.0
#   curl -sfL https://raw.githubusercontent.com/optiqor/kerno/main/scripts/install.sh | bash -s -- --daemon
#
# What it does:
#   1. Detects architecture (amd64/arm64)
#   2. Downloads the latest kerno binary from GitHub Releases
#   3. Installs to /usr/local/bin/kerno
#   4. Optionally installs systemd service (--daemon flag)
#
# Requirements:
#   - Linux kernel >= 5.8 with BTF (check: ls /sys/kernel/btf/vmlinux)
#   - Root access (or sudo)
#   - curl or wget

set -euo pipefail

REPO="optiqor/kerno"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/kerno"

# ── Parse arguments ──────────────────────────────────────────────────
VERSION=""
INSTALL_DAEMON=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --daemon)  INSTALL_DAEMON=true; shift ;;
        --help|-h)
            echo "Usage: curl -sfL https://raw.githubusercontent.com/optiqor/kerno/main/scripts/install.sh | bash -s -- [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --version VERSION   Install a specific version (default: latest)"
            echo "  --daemon            Also install systemd service for daemon mode"
            echo "  --help              Show this help"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Detect environment ───────────────────────────────────────────────
detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
    esac
}

detect_os() {
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    if [ "$os" != "linux" ]; then
        echo "Kerno only runs on Linux (got: $os)" >&2
        exit 1
    fi
    echo "$os"
}

check_btf() {
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        echo "WARNING: /sys/kernel/btf/vmlinux not found."
        echo "  Kerno requires a kernel with BTF support (>= 5.8)."
        echo "  On Ubuntu/Debian: sudo apt install linux-image-$(uname -r)"
        echo "  On Fedora/RHEL:   BTF is enabled by default on recent kernels."
        echo ""
        echo "  Continuing anyway — eBPF programs may fail to load."
    fi
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This installer needs root privileges."
        echo "Re-run with: curl -sfL https://raw.githubusercontent.com/optiqor/kerno/main/scripts/install.sh | sudo bash"
        exit 1
    fi
}

# ── Download ─────────────────────────────────────────────────────────
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

download() {
    local url="$1" dest="$2"
    if command -v curl &>/dev/null; then
        curl -fsSL -o "$dest" "$url"
    elif command -v wget &>/dev/null; then
        wget -qO "$dest" "$url"
    else
        echo "Neither curl nor wget found. Install one and retry." >&2
        exit 1
    fi
}

# ── Main ─────────────────────────────────────────────────────────────
main() {
    echo "==> Kerno installer - bare metal / VM / cloud instance"
    echo "    (For Kubernetes: helm install kerno ./deploy/helm/kerno)"
    echo ""

    check_root

    local os arch
    os=$(detect_os)
    arch=$(detect_arch)
    check_btf

    if [ -z "$VERSION" ]; then
        echo "==> Fetching latest version..."
        VERSION=$(get_latest_version)
    fi
    echo "==> Installing kerno ${VERSION} (${os}/${arch})"

    local tarball="kerno_${VERSION#v}_${os}_${arch}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${VERSION}/${tarball}"

    echo "==> Downloading ${url}"
    local tmp
    tmp=$(mktemp -d)
    download "$url" "${tmp}/${tarball}"

    echo "==> Extracting to ${INSTALL_DIR}/kerno"
    tar -xzf "${tmp}/${tarball}" -C "$tmp"
    install -m 755 "${tmp}/kerno" "${INSTALL_DIR}/kerno"
    rm -rf "$tmp"

    echo "==> Installed: $(kerno version 2>/dev/null || echo "${INSTALL_DIR}/kerno")"

    # ── Optional: systemd daemon ─────────────────────────────────────
    if [ "$INSTALL_DAEMON" = true ]; then
        echo ""
        echo "==> Installing systemd service..."

        mkdir -p "$CONFIG_DIR"

        # Download systemd unit and default config from repo.
        local raw="https://raw.githubusercontent.com/${REPO}/${VERSION}"
        download "${raw}/deploy/systemd/kerno.service" "${SYSTEMD_DIR}/kerno.service"

        if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
            download "${raw}/deploy/systemd/kerno.yaml" "${CONFIG_DIR}/config.yaml"
            echo "==> Default config written to ${CONFIG_DIR}/config.yaml"
        else
            echo "==> Config already exists at ${CONFIG_DIR}/config.yaml — not overwriting"
        fi

        systemctl daemon-reload
        systemctl enable kerno
        systemctl start kerno

        echo "==> Kerno daemon started. Check status: systemctl status kerno"
        echo "==> Logs: journalctl -u kerno -f"
        echo "==> Metrics: curl localhost:9090/metrics"
    fi

    echo ""
    echo "==> Done! Try it:"
    echo "    sudo kerno doctor"
    echo ""
}

main
