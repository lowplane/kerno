#!/usr/bin/env bash
# Copyright 2026 Optiqor contributors
# SPDX-License-Identifier: Apache-2.0
#
# soak-watch.sh — monitors kerno during a soak run.
# Scrapes RSS, goroutines, FDs, BPF maps, throughput, and pprof every N seconds.
#
# Usage:
#   ./scripts/soak-watch.sh [options]
#
# Options:
#   --duration      Total soak duration in seconds  (default: 86400)
#   --interval      Scrape interval in seconds       (default: 300)
#   --csv           Output CSV path                  (default: soak-results/metrics.csv)
#   --pprof-port    pprof HTTP port                  (default: 6060)
#   --metrics-port  Prometheus metrics port          (default: 9090)
#   --pprof-dir     Directory to save pprof dumps    (default: soak-results/pprof)
#   --pid           kerno PID to monitor             (required)

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
DURATION=86400
INTERVAL=300
CSV="soak-results/metrics.csv"
PPROF_PORT=6060
METRICS_PORT=9090
PPROF_DIR="soak-results/pprof"
KERNO_PID=""

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)     DURATION="$2";      shift 2 ;;
    --interval)     INTERVAL="$2";      shift 2 ;;
    --csv)          CSV="$2";           shift 2 ;;
    --pprof-port)   PPROF_PORT="$2";    shift 2 ;;
    --metrics-port) METRICS_PORT="$2";  shift 2 ;;
    --pprof-dir)    PPROF_DIR="$2";     shift 2 ;;
    --pid)          KERNO_PID="$2";     shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

if [[ -z "$KERNO_PID" ]]; then
  echo "ERROR: --pid is required" >&2
  exit 1
fi

mkdir -p "$PPROF_DIR"

# Write CSV header if file is empty or missing
if [[ ! -s "$CSV" ]]; then
  echo "ts_unix,rss_kb,goroutines,fds,bpf_maps,throughput_eps,doctor_p99_ms" > "$CSV"
fi

# ── Helper: scrape a Prometheus metric ──────────────────────────────────────
prometheus_metric() {
  local name="$1"
  curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep -E "^${name}[{ ]" \
    | awk '{print $NF}' \
    | head -1 || echo "N/A"
}

# ── Helper: rss in KB ────────────────────────────────────────────────────────
get_rss_kb() {
  if [[ -f "/proc/${KERNO_PID}/status" ]]; then
    grep VmRSS "/proc/${KERNO_PID}/status" | awk '{print $2}'
  else
    echo "N/A"
  fi
}

# ── Helper: goroutine count via pprof ────────────────────────────────────────
get_goroutines() {
  curl -sf "http://localhost:${PPROF_PORT}/debug/pprof/goroutine?debug=1" 2>/dev/null \
    | head -1 \
    | grep -oE '[0-9]+' \
    | head -1 || echo "N/A"
}

# ── Helper: open file descriptors ────────────────────────────────────────────
get_fds() {
  if [[ -d "/proc/${KERNO_PID}/fd" ]]; then
    ls /proc/${KERNO_PID}/fd 2>/dev/null | wc -l
  else
    echo "N/A"
  fi
}

# ── Helper: pinned BPF map count ─────────────────────────────────────────────
get_bpf_maps() {
  if command -v bpftool &>/dev/null; then
    sudo bpftool map list 2>/dev/null | grep -c "^[0-9]" || echo "0"
  else
    echo "N/A"
  fi
}

# ── Helper: save pprof snapshot ──────────────────────────────────────────────
save_pprof() {
  local ts="$1"
  curl -sf "http://localhost:${PPROF_PORT}/debug/pprof/heap" \
    -o "${PPROF_DIR}/heap_${ts}.pb.gz" 2>/dev/null || true
  curl -sf "http://localhost:${PPROF_PORT}/debug/pprof/goroutine" \
    -o "${PPROF_DIR}/goroutine_${ts}.pb.gz" 2>/dev/null || true
}

# ── Main loop ────────────────────────────────────────────────────────────────
START_TIME=$(date +%s)
END_TIME=$(( START_TIME + DURATION ))
TICK=0

echo "==> soak-watch started. Duration=${DURATION}s Interval=${INTERVAL}s PID=${KERNO_PID}"
echo "==> CSV: $CSV"
echo "==> End time: $(date -d @${END_TIME} 2>/dev/null || date -r ${END_TIME} 2>/dev/null || echo ${END_TIME})"

while true; do
  NOW=$(date +%s)
  [[ $NOW -ge $END_TIME ]] && break

  # Check kerno is still alive
  if ! kill -0 "$KERNO_PID" 2>/dev/null; then
    echo "ERROR: kerno process $KERNO_PID died at tick $TICK" >&2
    exit 1
  fi

  RSS=$(get_rss_kb)
  GOR=$(get_goroutines)
  FDS=$(get_fds)
  BPF=$(get_bpf_maps)
  TPS=$(prometheus_metric "kerno_events_total" || echo "N/A")
  P99=$(prometheus_metric "kerno_doctor_cycle_duration_seconds" || echo "N/A")

  # Convert p99 seconds → ms if numeric
  if [[ "$P99" =~ ^[0-9.]+$ ]]; then
    P99=$(echo "$P99 * 1000" | bc -l | xargs printf "%.2f")
  fi

  echo "${NOW},${RSS},${GOR},${FDS},${BPF},${TPS},${P99}" >> "$CSV"

  echo "[tick=${TICK} elapsed=$(( (NOW - START_TIME) / 60 ))min] RSS=${RSS}KB GOR=${GOR} FDs=${FDS} BPF=${BPF} TPS=${TPS} p99=${P99}ms"

  # Save pprof at hour 1, hour 6, hour 12, hour 18, hour 24
  ELAPSED=$(( NOW - START_TIME ))
  for checkpoint in 3600 21600 43200 64800 86400; do
    if (( ELAPSED >= checkpoint && ELAPSED < checkpoint + INTERVAL )); then
      echo "==> Saving pprof snapshot at ${checkpoint}s checkpoint"
      save_pprof "${checkpoint}s"
    fi
  done

  TICK=$(( TICK + 1 ))
  sleep "$INTERVAL"
done

echo "==> soak-watch complete. $(( TICK )) snapshots written to $CSV"
