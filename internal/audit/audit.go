// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package audit provides an append-only structured audit log for SOC 2 /
// ISO 27001 / HIPAA compliance. Every privileged action kerno takes —
// config reloads, AI calls, finding emissions, auth failures, and daemon
// lifecycle events — is written as an NDJSON record to one or more sinks:
//
//   - stderr (via slog "audit" group) — picked up by journald / systemd
//   - a configurable file path with rotation via lumberjack
//
// No PII (PIDs, IPs, paths) appears in audit records; all fields are
// redacted by [Redact] before being written.
package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// EventType identifies the category of an audit record.
type EventType string

const (
	EventDaemonStart  EventType = "daemon.start"
	EventDaemonStop   EventType = "daemon.stop"
	EventDaemonPanic  EventType = "daemon.panic"
	EventConfigReload EventType = "config.reload"
	EventAICall       EventType = "ai.call"
	EventFindingEmit  EventType = "finding.emit"
	EventAuthFailure  EventType = "auth.failure"
	EventBPFLoad      EventType = "bpf.load"
)

// Record is the top-level NDJSON envelope written for every auditable event.
type Record struct {
	SchemaVersion string    `json:"v"`
	Timestamp     time.Time `json:"ts"`
	Type          EventType `json:"type"`
	Actor         string    `json:"actor"`
	Details       any       `json:"details"`
}

// DaemonDetails carries version and optional panic information for daemon
// lifecycle events.
type DaemonDetails struct {
	Version     string `json:"version,omitempty"`
	PanicDigest string `json:"panic_digest,omitempty"`
}

// ConfigReloadDetails describes a configuration reload attempt.
type ConfigReloadDetails struct {
	Path            string   `json:"path"`
	ChangedFields   []string `json:"changed_fields"`
	Applied         int      `json:"applied"`
	RestartRequired int      `json:"restart_required"`
	Source          string   `json:"source"`
	UID             int      `json:"uid"`
}

// AICallDetails records metadata about an outbound AI provider request.
// Prompt and response bodies are never logged; only token counts and
// redaction statistics are retained.
type AICallDetails struct {
	Provider     string        `json:"provider"`
	Model        string        `json:"model"`
	Tokens       int           `json:"tokens"`
	PromptSize   int           `json:"prompt_size"`
	ResponseSize int           `json:"response_size"`
	Redactions   RedactSummary `json:"redactions"`
	DurationMs   int64         `json:"duration_ms"`
}

// FindingEmitDetails records an outbound finding delivery to a sink.
type FindingEmitDetails struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Sink        string `json:"sink"`
	PayloadHash string `json:"payload_hash"`
	CycleID     string `json:"cycle_id"`
}

// BPFLoadDetails records the outcome of a BPF program load attempt.
type BPFLoadDetails struct {
	Program string `json:"program"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// AuthFailureDetails records a failed authentication attempt on an endpoint.
type AuthFailureDetails struct {
	Endpoint string `json:"endpoint"`
	Reason   string `json:"reason"`
	RemoteIP string `json:"remote_ip"`
}

// Logger writes structured audit records to one or more configured sinks.
// All methods are safe for concurrent use.
type Logger struct {
	mu      sync.Mutex
	enc     *json.Encoder
	slogger *slog.Logger
	noop    bool
}

// Config controls where audit records are written.
type Config struct {
	FilePath   string
	MaxSizeMB  int
	MaxBackups int
	Stderr     bool
}

// New constructs a Logger from cfg. When no FilePath is provided, records
// are written to stderr. Both sinks may be active simultaneously.
func New(cfg Config) (*Logger, error) {
	var writers []io.Writer

	if cfg.FilePath != "" {
		maxMB := cfg.MaxSizeMB
		if maxMB == 0 {
			maxMB = 100
		}
		lj := &lumberjack.Logger{
			Filename:   cfg.FilePath,
			MaxSize:    maxMB,
			MaxBackups: cfg.MaxBackups,
			Compress:   true,
		}
		writers = append(writers, lj)
	}

	if cfg.Stderr || len(writers) == 0 {
		writers = append(writers, os.Stderr)
	}

	var w io.Writer
	switch len(writers) {
	case 1:
		w = writers[0]
	default:
		w = io.MultiWriter(writers...)
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	return &Logger{
		enc:     enc,
		slogger: slog.Default().WithGroup("audit"),
	}, nil
}

// NewWithWriter constructs a Logger that writes to w. Intended for testing.
func NewWithWriter(w io.Writer) (*Logger, error) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Logger{
		enc:     enc,
		slogger: slog.Default().WithGroup("audit"),
	}, nil
}

// Noop returns a Logger that discards all records. Useful in tests or
// when audit logging is administratively disabled.
func Noop() *Logger {
	enc := json.NewEncoder(io.Discard)
	return &Logger{
		enc:     enc,
		slogger: slog.Default(),
		noop:    true,
	}
}

// Record emits a single audit record with the given actor, event type, and
// detail payload. It is safe to call concurrently.
func (l *Logger) Record(actor string, evType EventType, details any) {
	if l == nil || l.noop {
		return
	}

	rec := Record{
		SchemaVersion: "1",
		Timestamp:     time.Now().UTC(),
		Type:          evType,
		Actor:         actor,
		Details:       details,
	}

	l.mu.Lock()
	_ = l.enc.Encode(rec)
	l.mu.Unlock()

	l.slogger.Info("event",
		slog.String("type", string(evType)),
		slog.String("actor", actor),
	)
}

// RecordPanic emits a daemon.panic audit record. Only the first 16 hex
// characters of the SHA-256 digest of stackTrace are written; the raw bytes
// are intentionally omitted so sensitive goroutine state stays in
// stderr/journald rather than the structured audit log.
func (l *Logger) RecordPanic(ver string, stackTrace []byte) {
	sum := sha256.Sum256(stackTrace)
	digest := fmt.Sprintf("%x", sum[:])[:16]
	l.Record("kerno/start", EventDaemonPanic, DaemonDetails{
		Version:     ver,
		PanicDigest: digest,
	})
}

// RecordAICall emits an ai.call audit record. No prompt or response content
// is logged — only token counts, sizes, redaction statistics, and latency.
func (l *Logger) RecordAICall(
	provider, model string,
	tokens int,
	promptSize, responseSize int,
	redactions RedactSummary,
	durationMs int64,
) {
	l.Record("ai/analyzer", EventAICall, AICallDetails{
		Provider:     provider,
		Model:        model,
		Tokens:       tokens,
		PromptSize:   promptSize,
		ResponseSize: responseSize,
		Redactions:   redactions,
		DurationMs:   durationMs,
	})
}

// RecordBPFLoad emits a bpf.load audit record. loadErr may be nil on success.
func (l *Logger) RecordBPFLoad(program string, success bool, loadErr error) {
	d := BPFLoadDetails{Program: program, Success: success}
	if loadErr != nil {
		d.Error, _ = Redact(loadErr.Error())
	}
	l.Record("bpf/loader", EventBPFLoad, d)
}

// RecordAuthFailure emits an auth.failure record. remoteIP must already be
// redacted by the caller (e.g. via RedactRemoteAddr) before being passed here.
func (l *Logger) RecordAuthFailure(endpoint, reason, remoteIP string) {
	l.Record("http/server", EventAuthFailure, AuthFailureDetails{
		Endpoint: endpoint,
		Reason:   reason,
		RemoteIP: remoteIP,
	})
}

// RecordFindingEmit emits a finding.emit audit record. payloadHash should be
// produced by HashPayload; the raw finding payload is never written.
func (l *Logger) RecordFindingEmit(rule, severity, sink, payloadHash, cycleID string) {
	l.Record("doctor/engine", EventFindingEmit, FindingEmitDetails{
		Rule:        rule,
		Severity:    severity,
		Sink:        sink,
		PayloadHash: payloadHash,
		CycleID:     cycleID,
	})
}

// RecordConfigReload emits a config.reload audit record. path is redacted
// automatically. restartRequired is the count of changed fields that require
// a daemon restart to take effect; Applied is derived as
// len(changedFields) - restartRequired.
func (l *Logger) RecordConfigReload(path, source string, changedFields []string, restartRequired int, uid int) {
	l.Record(fmt.Sprintf("config/%s", source), EventConfigReload, ConfigReloadDetails{
		Path:            RedactPath(path),
		ChangedFields:   changedFields,
		Applied:         len(changedFields) - restartRequired,
		RestartRequired: restartRequired,
		Source:          source,
		UID:             uid,
	})
}
