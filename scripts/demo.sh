#!/usr/bin/env bash
# Copyright 2026 Optiqor contributors
# SPDX-License-Identifier: Apache-2.0
#
# demo.sh — runs the kerno doctor demo scenario for asciinema/vhs.
#
# This script orchestrates the same flow as demo.tape but is callable
# directly so asciinema can record it. It's also the canonical "show
# me what kerno can do" entry point — anyone with kerno + sudo can run
# it on a real machine and see the doctor catch the synthetic incident.

set -euo pipefail
cd "$(dirname "$0")/.."

KERNO=${KERNO:-bin/kerno}

if [[ ! -x "$KERNO" ]]; then
    # The demo loads real BPF programs, so build with the ebpf tag.
    # `make build` (default) produces stubs that can't actually trace.
    echo "Building kerno (real BPF mode)..."
    make build-ebpf >/dev/null
fi

clear
cat <<'INTRO'
# Kerno doctor — eBPF-based incident diagnosis
# ============================================
INTRO
sleep 2

echo
echo "# Step 1: induce a synthetic disk-fsync bottleneck in the background"
sleep 1
"$KERNO" chaos --induce disk-sat --duration 25s --intensity high --yes \
    >/tmp/kerno-demo-chaos.log 2>&1 &
CPID=$!
sleep 2

echo
echo "# Step 2: ask kerno to diagnose the system"
sleep 1
sudo "$KERNO" --config scripts/verify-config.yaml \
    doctor --duration 12s

wait $CPID 2>/dev/null || true

echo
echo "# Done. Same flow runs in CI via 'make verify'."
sleep 3
