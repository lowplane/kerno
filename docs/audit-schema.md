# Kerno Audit Log — Schema Reference

**Schema version:** `1`  
**Format:** NDJSON (Newline-Delimited JSON) — one JSON object per line  
**File:** `/var/log/kerno-audit.jsonl` (configurable via `audit.file_path`)  
**Encoding:** UTF-8, `SetEscapeHTML(false)` — slashes in paths are not mangled

---

## Why this log exists

Compliance frameworks (SOC 2, ISO 27001, HIPAA) require an **append-only audit trail** of every privileged action a daemon takes: who triggered it, when, and what changed. Kerno's operational log (`slog`) records health and debug information; this audit log records **security-relevant events** only.

A compliance reviewer can:
1. Trace a finding from sink emission → AI call → doctor cycle → eBPF signal.
2. Verify that no PII (PIDs, IPs, filesystem paths) appears in any record.
3. Confirm that every config change was source-attributed (file, SIGHUP, env).

---

## Envelope (all records)

Every line is a JSON object with this envelope:

```json
{
  "v":      "1",
  "ts":     "2026-05-10T14:32:01.123Z",
  "type":   "<event-type>",
  "actor":  "<subsystem/component>",
  "details": { ... }
}
```

| Field | Type | Description |
|---|---|---|
| `v` | string | Schema version. Currently `"1"`. Increment when fields are added or removed. |
| `ts` | RFC 3339 (UTC) | Wall-clock timestamp when the record was written. |
| `type` | string | Event category. See table below. |
| `actor` | string | Kerno subsystem that emitted the record (e.g. `"kerno/start"`, `"ai/analyzer"`). |
| `details` | object | Event-specific payload. Schema per `type` documented below. |

---

## Event types

| `type` | Trigger |
|---|---|
| `daemon.start` | Daemon process started |
| `daemon.stop` | Daemon process stopped (graceful or signal) |
| `daemon.panic` | Daemon panic recovered; stack trace digest included |
| `config.reload` | Config file reloaded (initial load or SIGHUP) |
| `ai.call` | LLM provider called (success or failure) |
| `finding.emit` | Diagnostic finding emitted to a downstream sink |
| `auth.failure` | `/metrics` bearer-token mismatch or mTLS failure |
| `bpf.load` | eBPF program loaded or failed to load |

---

## `daemon.start` / `daemon.stop`

```json
{
  "v": "1",
  "ts": "2026-05-10T14:30:00.000Z",
  "type": "daemon.start",
  "actor": "kerno/start",
  "details": {
    "version": "v0.3.1"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `version` | string | Kerno binary version (`version.Version`). |

---

## `daemon.panic`

```json
{
  "v": "1",
  "ts": "2026-05-10T15:00:00.000Z",
  "type": "daemon.panic",
  "actor": "kerno/start",
  "details": {
    "version": "v0.3.1",
    "panic_digest": "a3f1b2c4d5e6f708"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `version` | string | Kerno binary version. |
| `panic_digest` | string | First 16 hex characters of `SHA-256(stack_trace)`. The full trace goes to the operational log (stderr); this digest lets you correlate without storing the trace here. |

---

## `config.reload`

```json
{
  "v": "1",
  "ts": "2026-05-10T14:32:05.000Z",
  "type": "config.reload",
  "actor": "config/SIGHUP",
  "details": {
    "path": "/etc/<redacted>",
    "changed_fields": ["log_level", "doctor.thresholds.fsync_p99_critical_ns"],
    "applied": 2,
    "restart_required": 0,
    "source": "SIGHUP",
    "uid": 0
  }
}
```

| Field | Type | Description |
|---|---|---|
| `path` | string | Redacted config file path (top-level dir only, e.g. `/etc/<redacted>`). |
| `changed_fields` | string[] | Dot-notation field names that differed from the previous config. |
| `applied` | int | Number of fields applied without restart. |
| `restart_required` | int | Number of fields that require a daemon restart to take effect. |
| `source` | string | `"file"`, `"SIGHUP"`, or `"env"`. |
| `uid` | int | UID of the process that triggered the reload. |

---

## `ai.call`

```json
{
  "v": "1",
  "ts": "2026-05-10T14:32:01.123Z",
  "type": "ai.call",
  "actor": "ai/analyzer",
  "details": {
    "provider": "anthropic",
    "model": "claude-sonnet-4-20250514",
    "tokens": 412,
    "prompt_size": 1024,
    "response_size": 380,
    "redactions": {
      "pid": 3,
      "ip": 1,
      "path": 0
    },
    "duration_ms": 854
  }
}
```

**Privacy guarantee:** Prompt and response bodies are **never** included. Only byte lengths and redaction counts are recorded. The `redactions` object lets a compliance reviewer verify that the privacy mode ran and stripped PII before the prompt was sent.

| Field | Type | Description |
|---|---|---|
| `provider` | string | `"anthropic"`, `"openai"`, or `"ollama"`. |
| `model` | string | Model identifier returned by the provider. `"cached"` for cache hits; `"unknown"` on error. |
| `tokens` | int | Total tokens used (input + output). 0 for cache hits and errors. |
| `prompt_size` | int | Byte length of the user prompt **before** redaction. |
| `response_size` | int | Byte length of the raw completion text. 0 for cache hits and errors. |
| `redactions.pid` | int | Number of PID patterns stripped from the prompt. |
| `redactions.ip` | int | Number of IPv4 addresses stripped from the prompt. |
| `redactions.path` | int | Number of filesystem paths stripped from the prompt. |
| `duration_ms` | int | Wall-clock milliseconds from provider call start to response. 0 for cache hits. |

---

## `finding.emit`

```json
{
  "v": "1",
  "ts": "2026-05-10T14:32:10.000Z",
  "type": "finding.emit",
  "actor": "doctor/engine",
  "details": {
    "rule": "oom_pressure",
    "severity": "CRITICAL",
    "sink": "slack",
    "payload_hash": "a1b2c3d4e5f60708",
    "cycle_id": "cycle-20260510-143200"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `rule` | string | Diagnostic rule that produced the finding. |
| `severity` | string | `"CRITICAL"`, `"WARNING"`, or `"INFO"`. |
| `sink` | string | Downstream sink: `"slack"`, `"pagerduty"`, `"log"`, etc. |
| `payload_hash` | string | FNV-1a (16 hex chars) of the serialised payload. Links this record to the payload without exposing PII. |
| `cycle_id` | string | Identifier for the doctor run that produced this finding. Links to the `ai.call` record for the same cycle. |

---

## `auth.failure`

```json
{
  "v": "1",
  "ts": "2026-05-10T14:33:00.000Z",
  "type": "auth.failure",
  "actor": "http/server",
  "details": {
    "endpoint": "/metrics",
    "reason": "token_mismatch",
    "remote_ip": "<ip-redacted>"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `endpoint` | string | HTTP path that was accessed. |
| `reason` | string | `"token_mismatch"` or `"mtls_failure"`. |
| `remote_ip` | string | Always `<ip-redacted>` — the raw IP is never written to the audit log. |

---

## `bpf.load`

```json
{
  "v": "1",
  "ts": "2026-05-10T14:30:01.000Z",
  "type": "bpf.load",
  "actor": "bpf/loader",
  "details": {
    "program": "syscall_latency",
    "success": true
  }
}
```

```json
{
  "v": "1",
  "ts": "2026-05-10T14:30:01.100Z",
  "type": "bpf.load",
  "actor": "bpf/loader",
  "details": {
    "program": "tcp_monitor",
    "success": false,
    "error": "operation not permitted"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `program` | string | eBPF program name (matches `bpf.Loader.Name()`). |
| `success` | bool | `true` if the program loaded successfully. |
| `error` | string | Error message. Present only when `success` is `false`. |

---

## PII redaction

Kerno **never** writes PIDs, raw IPv4 addresses, or full filesystem paths to the audit log.

| PII category | Replacement |
|---|---|
| `pid=<n>` / `PID: <n>` | `pid=<redacted>` |
| IPv4 address | `<ip-redacted>` |
| Absolute path under `/etc`, `/home`, `/var`, `/tmp`, `/proc`, `/sys`, `/run`, `/opt`, `/usr` | `/<top-level-dir>/<redacted>` |

The `redactions` object in `ai.call` records counts how many items of each category were stripped before the prompt was sent to the provider. A count of `0` means the privacy filter ran and found nothing to strip — not that it was skipped.

---

## Log rotation

File rotation is handled by [lumberjack](https://github.com/natefinch/lumberjack):

| Config key | Default | Description |
|---|---|---|
| `audit.file_path` | `/var/log/kerno-audit.jsonl` | Absolute path. Empty string disables the file sink. |
| `audit.max_size_mb` | `100` | Rotate when the file reaches this size in MB. |
| `audit.max_backups` | `0` | Number of rotated files to keep. `0` = unlimited (no auto-deletion). Set a non-zero value only if storage is constrained and your retention policy permits it. |
| `audit.stderr` | `true` | Also emit records to stderr (journald-friendly). |

Rotated files are named `kerno-audit-<timestamp>.jsonl.gz` by lumberjack. If you use an external log shipper (Fluentd, Vector, Promtail), point it at the directory and enable glob matching for `*.jsonl*`.

---

## Tracing a finding end-to-end

```
bpf.load   program=syscall_latency success=true
                    ↓
ai.call    provider=anthropic tokens=412 cycle_id=cycle-abc123
                    ↓
finding.emit rule=syscall_latency_critical sink=slack cycle_id=cycle-abc123
             payload_hash=a1b2c3d4e5f60708
```

1. Filter `bpf.load` records for the relevant program.
2. Find the `ai.call` record whose `ts` is closest after the eBPF programs loaded.
3. Match `finding.emit` records by `cycle_id` to correlate the AI call with the finding.
4. Use `payload_hash` to verify the payload delivered to Slack/PagerDuty matches the audit record.

---

## Schema versioning

The `"v"` field is bumped when:
- A **required** field is added or removed from any details payload.
- The semantics of an existing field change in a backward-incompatible way.

Adding **optional** fields (present only sometimes) does **not** bump the version.  
Log shippers and parsers should treat unknown fields as forward-compatible extensions.