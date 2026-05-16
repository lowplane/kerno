# Soak Test

A 24-hour continuous load test that catches slow resource leaks before they reach production.

## Why

Unit tests, race tests, and 5-minute integration tests cannot expose:

- Goroutine leaks where spawn-rate exceeds GC cleanup
- Handle leaks from pinned BPF maps or accumulating ringbuf readers
- Histogram allocation cliffs under high label cardinality
- BPF map fragmentation under sustained churn

These fail at hour 14 in production. The soak finds them in CI first.

## How It Works

The nightly workflow (`.github/workflows/soak.yml`) runs on `ubuntu-22.04` and:

1. Builds and installs kerno with `make build` and `setcap`
2. Launches `kerno start` with metrics and pprof endpoints exposed
3. Launches `kerno chaos --induce cascade --duration 86400s` in the background
4. Every 5 minutes: scrapes RSS, goroutine count, open FDs, pinned BPF maps, event throughput, and doctor p99 latency into a CSV
5. Saves heap and goroutine pprof snapshots at hours 1, 6, 12, 18, and 24
6. At the end: asserts all pass criteria and uploads the full artifact

## Pass Criteria

| Metric | Limit |
|---|---|
| RSS at hour 24 | < 1.5× RSS at hour 1 |
| Goroutine count at hour 24 | ≤ goroutine count at hour 1 + 50 |
| Open FDs post-warmup | flat (delta ≤ 50) |
| Panics / Fatals | zero |
| Throughput stability | CV ≤ 0.20 (±20% across the run) |

## Running Locally

```bash
# Build kerno
make build
sudo setcap 'cap_bpf,cap_perfmon,cap_sys_ptrace,cap_sys_admin,cap_net_admin,cap_dac_read_search+ep' ./bin/kerno

# Prepare output dir
mkdir -p soak-results/pprof

# Start kerno
./bin/kerno start --metrics-addr :9090 --pprof-addr :6060 &
KERNO_PID=$!

# Start chaos (reduce duration for local testing)
./bin/kerno chaos --induce cascade --duration 3600s &

# Run the watcher (1 hour, 5-min intervals)
bash scripts/soak-watch.sh \
  --duration 3600 \
  --interval 300 \
  --csv soak-results/metrics.csv \
  --pprof-port 6060 \
  --metrics-port 9090 \
  --pprof-dir soak-results/pprof \
  --pid $KERNO_PID
```

For a quick smoke test use `--duration 600 --interval 60` (10 minutes, 1-minute intervals).

## Interpreting a Failed Run

Download the artifact from the GitHub Actions run. It contains:

| File | Contents |
|---|---|
| `metrics.csv` | Full time-series of all scraped metrics |
| `kerno.log` | Full daemon log including any panics |
| `chaos.log` | Chaos injector log |
| `pprof/heap_Xs.pb.gz` | Heap profile at checkpoint X seconds |
| `pprof/goroutine_Xs.pb.gz` | Goroutine dump at checkpoint X seconds |

### RSS leak

```bash
# Compare heap profiles between hour 1 and hour 24
go tool pprof -diff_base soak-results/pprof/heap_3600s.pb.gz \
                          soak-results/pprof/heap_86400s.pb.gz
```

Look for allocations that grew between checkpoints.

### Goroutine leak

```bash
# View goroutine dump at hour 24
go tool pprof soak-results/pprof/goroutine_86400s.pb.gz
(pprof) top
(pprof) traces
```

Look for goroutines blocked on channels or waiting in the same function across all dumps.

### FD leak

```bash
# Check CSV for FD column trend
awk -F, 'NR>1 {print $1, $5}' soak-results/metrics.csv | \
  awk '{printf "%s min  FDs=%s\n", int(($1-start)/60), $2; if(NR==1) start=$1}'
```

A steadily rising FD count after the 30-minute warmup indicates a handle leak.

## Nightly Schedule

The workflow runs at **02:00 UTC daily** via cron. Runtime is approximately 24 hours and 20 minutes including setup and assertion steps.

GitHub Actions free tier provides 2000 minutes/month for private repos and unlimited for public repos. At ~1460 minutes per run, one nightly soak on a public repo fits within limits.

## Soak Badge

Add to `README.md`:

```markdown
[![Soak](https://github.com/optiqor/kerno/actions/workflows/soak.yml/badge.svg)](https://github.com/optiqor/kerno/actions/workflows/soak.yml)
```
