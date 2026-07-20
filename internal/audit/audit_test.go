// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/audit"
)

// Redact: PID
func TestRedact_PID(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantPIDs    int
		wantAbsent  string
		wantPresent string
	}{
		{
			name:        "pid equals",
			input:       "process pid=1234 crashed",
			wantPIDs:    1,
			wantAbsent:  "1234",
			wantPresent: "pid=<redacted>",
		},
		{
			name:        "pid colon",
			input:       "PID: 99 killed",
			wantPIDs:    1,
			wantAbsent:  "99",
			wantPresent: "pid=<redacted>",
		},
		{
			name:        "multiple pids",
			input:       "pid=10 and pid=20 racing",
			wantPIDs:    2,
			wantAbsent:  "pid=10",
			wantPresent: "pid=<redacted>",
		},
		{
			name:     "no pid",
			input:    "nothing sensitive here",
			wantPIDs: 0,
		},
		// Regression: "pid count 99" must NOT match — only pid= and pid: forms.
		{
			name:     "pid word boundary no match",
			input:    "the pid count is 99",
			wantPIDs: 0,
		},
		// Regression: ensure pid=<redacted> token does not re-match on second pass.
		{
			name:        "already redacted token is stable",
			input:       "pid=<redacted>",
			wantPIDs:    0,
			wantPresent: "pid=<redacted>",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, sum := audit.Redact(tc.input)
			if sum.PIDs != tc.wantPIDs {
				t.Errorf("PIDs: want %d got %d (output: %q)", tc.wantPIDs, sum.PIDs, got)
			}
			if tc.wantPresent != "" && !strings.Contains(got, tc.wantPresent) {
				t.Errorf("want %q in output %q", tc.wantPresent, got)
			}
			if tc.wantAbsent != "" && strings.Contains(got, tc.wantAbsent) {
				t.Errorf("PII %q must NOT appear in output %q", tc.wantAbsent, got)
			}
		})
	}
}

// Redact: IP

func TestRedact_IP(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantIPs    int
		wantAbsent string
	}{
		{"single ip", "connected to 192.168.1.100", 1, "192.168.1.100"},
		{"two ips", "src=10.0.0.1 dst=10.0.0.2", 2, "10.0.0.1"},
		{"loopback", "listening on 127.0.0.1:8080", 1, "127.0.0.1"},
		{"no ip", "no addresses here", 0, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, sum := audit.Redact(tc.input)
			if sum.IPs != tc.wantIPs {
				t.Errorf("IPs: want %d got %d", tc.wantIPs, sum.IPs)
			}
			if tc.wantAbsent != "" && strings.Contains(got, tc.wantAbsent) {
				t.Errorf("IP %q must not appear in %q", tc.wantAbsent, got)
			}
			if tc.wantIPs > 0 && !strings.Contains(got, "<ip-redacted>") {
				t.Errorf("want <ip-redacted> placeholder in %q", got)
			}
		})
	}
}

// Redact: path

func TestRedact_Path(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantPaths   int
		wantAbsent  string
		wantPresent string
	}{
		{"etc path", "reading /etc/kerno/config.yaml", 1, "/etc/kerno/config.yaml", "/etc/<redacted>"},
		{"var log path", "writing /var/log/kerno-audit.jsonl", 1, "/var/log/kerno-audit.jsonl", ""},
		{"home path", "found /home/ubuntu/.ssh/id_rsa", 1, "/home/ubuntu/.ssh/id_rsa", ""},
		{"no path", "no filesystem paths here", 0, "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, sum := audit.Redact(tc.input)
			if sum.Paths != tc.wantPaths {
				t.Errorf("Paths: want %d got %d", tc.wantPaths, sum.Paths)
			}
			if tc.wantAbsent != "" && strings.Contains(got, tc.wantAbsent) {
				t.Errorf("path %q must not appear in %q", tc.wantAbsent, got)
			}
			if tc.wantPresent != "" && !strings.Contains(got, tc.wantPresent) {
				t.Errorf("want prefix %q in %q", tc.wantPresent, got)
			}
		})
	}
}

//  Redact: idempotency

func TestRedact_Idempotent(t *testing.T) {
	input := "pid=42 connected from 10.0.0.1 reading /etc/passwd"
	first, _ := audit.Redact(input)
	second, sum2 := audit.Redact(first)

	if first != second {
		t.Errorf("redact is not idempotent:\nfirst:  %q\nsecond: %q", first, second)
	}
	if sum2.PIDs != 0 || sum2.IPs != 0 {
		t.Errorf("second pass found residual PII: %+v", sum2)
	}
}

func TestRedact_NoPIILeak(t *testing.T) {
	sensitive := []string{"192.168.1.1", "10.0.0.50", "/etc/shadow", "/home/alice/.ssh"}
	input := "pid=1 ip=192.168.1.1 and 10.0.0.50 file=/etc/shadow key=/home/alice/.ssh/id_rsa"
	got, _ := audit.Redact(input)
	for _, s := range sensitive {
		if strings.Contains(got, s) {
			t.Errorf("PII %q leaked into redacted output: %q", s, got)
		}
	}
}

//  RedactPath

func TestRedactPath(t *testing.T) {
	cases := map[string]string{
		"/etc/kerno/config.yaml":     "/etc/<redacted>",
		"/var/log/kerno-audit.jsonl": "/var/<redacted>",
		"/home/alice/.bash_history":  "/home/<redacted>",
		"relative/path":              "<path-redacted>",
		"/":                          "<path-redacted>",
	}
	for in, want := range cases {
		got := audit.RedactPath(in)
		if got != want {
			t.Errorf("RedactPath(%q) = %q, want %q", in, got, want)
		}
	}
}

//  RedactRemoteAddr

func TestRedactRemoteAddr(t *testing.T) {
	cases := map[string]string{
		// IPv4 TCP
		"192.168.1.1:54321": "<ip-redacted>",
		"10.0.0.5:8080":     "<ip-redacted>",
		// IPv6 TCP — net.SplitHostPort handles bracket stripping
		"[::1]:9090":           "<ip-redacted>",
		"[::ffff:1.2.3.4]:443": "<ip-redacted>",
		// Unix domain socket — net.SplitHostPort fails → path-redacted
		"/var/run/app.sock": "<path-redacted>",
	}
	for in, want := range cases {
		got := audit.RedactRemoteAddr(in)
		if got != want {
			t.Errorf("RedactRemoteAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

//  HashPayload

func TestHashPayload_Deterministic(t *testing.T) {
	h1 := audit.HashPayload("rule=oom severity=critical")
	h2 := audit.HashPayload("rule=oom severity=critical")
	if h1 != h2 {
		t.Errorf("hash not deterministic: %q != %q", h1, h2)
	}
}

func TestHashPayload_Different(t *testing.T) {
	h1 := audit.HashPayload("rule=oom severity=critical")
	h2 := audit.HashPayload("rule=tcp severity=warning")
	if h1 == h2 {
		t.Errorf("different inputs produced same hash: %q", h1)
	}
}

func TestHashPayload_Length(t *testing.T) {
	h := audit.HashPayload("anything")
	if len(h) != 16 {
		t.Errorf("hash length: want 16, got %d (%q)", len(h), h)
	}
}

//  Logger helpers

func captureLogger(t *testing.T) (*audit.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	l, err := audit.NewWithWriter(&buf)
	if err != nil {
		t.Fatalf("audit.NewWithWriter: %v", err)
	}
	return l, &buf
}

//  Logger: schema

func TestLogger_RecordSchema(t *testing.T) {
	l, buf := captureLogger(t)

	l.Record("kerno/start", audit.EventDaemonStart, audit.DaemonDetails{Version: "v0.1.0"})

	var rec audit.Record
	if err := json.NewDecoder(buf).Decode(&rec); err != nil {
		t.Fatalf("decode audit record: %v", err)
	}
	if rec.SchemaVersion != "1" {
		t.Errorf("SchemaVersion: want 1, got %q", rec.SchemaVersion)
	}
	if rec.Type != audit.EventDaemonStart {
		t.Errorf("Type: want %q, got %q", audit.EventDaemonStart, rec.Type)
	}
	if rec.Actor != "kerno/start" {
		t.Errorf("Actor: want kerno/start, got %q", rec.Actor)
	}
	if rec.Timestamp.IsZero() {
		t.Error("Timestamp must not be zero")
	}
	if rec.Timestamp.Location() != time.UTC {
		t.Error("Timestamp must be UTC")
	}
}

//  Logger: ai.call

func TestLogger_RecordAICall(t *testing.T) {
	l, buf := captureLogger(t)

	l.RecordAICall("anthropic", "claude-sonnet-4-20250514", 412, 800, 200,
		audit.RedactSummary{PIDs: 3, IPs: 1, Paths: 0}, 854)

	var rec audit.Record
	if err := json.NewDecoder(buf).Decode(&rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Type != audit.EventAICall {
		t.Errorf("Type: want ai.call, got %q", rec.Type)
	}

	raw, _ := json.Marshal(rec.Details)
	var d audit.AICallDetails
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal AICallDetails: %v", err)
	}
	if d.Provider != "anthropic" {
		t.Errorf("Provider: want anthropic, got %q", d.Provider)
	}
	if d.Tokens != 412 {
		t.Errorf("Tokens: want 412, got %d", d.Tokens)
	}
	if d.Redactions.PIDs != 3 {
		t.Errorf("Redactions.PIDs: want 3, got %d", d.Redactions.PIDs)
	}
}

//  Logger: bpf.load

func TestLogger_RecordBPFLoad_Failure(t *testing.T) {
	l, buf := captureLogger(t)

	l.RecordBPFLoad("syscall_latency", false, testError("permission denied"))

	var rec audit.Record
	if err := json.NewDecoder(buf).Decode(&rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw, _ := json.Marshal(rec.Details)
	var d audit.BPFLoadDetails
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal BPFLoadDetails: %v", err)
	}
	if d.Success {
		t.Error("Success must be false for a failure event")
	}
	if d.Error == "" {
		t.Error("Error must be non-empty for a failure event")
	}
}

func TestLogger_RecordBPFLoad_Success(t *testing.T) {
	l, buf := captureLogger(t)
	l.RecordBPFLoad("tcp_monitor", true, nil)

	var rec audit.Record
	if err := json.NewDecoder(buf).Decode(&rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw, _ := json.Marshal(rec.Details)
	var d audit.BPFLoadDetails
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal BPFLoadDetails: %v", err)
	}
	if !d.Success {
		t.Error("Success must be true")
	}
	if d.Error != "" {
		t.Errorf("Error must be empty on success, got %q", d.Error)
	}
}

//  Logger: auth.failure

func TestLogger_RecordAuthFailure(t *testing.T) {
	l, buf := captureLogger(t)
	l.RecordAuthFailure("/metrics", "token_mismatch", "<ip-redacted>")

	var rec audit.Record
	if err := json.NewDecoder(buf).Decode(&rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Type != audit.EventAuthFailure {
		t.Errorf("Type: want auth.failure, got %q", rec.Type)
	}
}

//  Logger: finding.emit

func TestLogger_RecordFindingEmit(t *testing.T) {
	l, buf := captureLogger(t)
	hash := audit.HashPayload(`{"rule":"oom","severity":"critical"}`)
	l.RecordFindingEmit("oom_pressure", "CRITICAL", "slack", hash, "cycle-abc123")

	var rec audit.Record
	if err := json.NewDecoder(buf).Decode(&rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Type != audit.EventFindingEmit {
		t.Errorf("Type: want finding.emit, got %q", rec.Type)
	}
	raw, _ := json.Marshal(rec.Details)
	var d audit.FindingEmitDetails
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal FindingEmitDetails: %v", err)
	}
	if d.PayloadHash == "" {
		t.Error("PayloadHash must not be empty")
	}
	if d.CycleID != "cycle-abc123" {
		t.Errorf("CycleID: want cycle-abc123, got %q", d.CycleID)
	}
}

//  Logger: daemon.panic

func TestLogger_RecordPanic(t *testing.T) {
	l, buf := captureLogger(t)

	fakeStack := []byte("goroutine 1 [running]:\nmain.main()\n\t/src/main.go:42")
	l.RecordPanic("v0.3.1", fakeStack)

	var rec audit.Record
	if err := json.NewDecoder(buf).Decode(&rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Type != audit.EventDaemonPanic {
		t.Errorf("Type: want daemon.panic, got %q", rec.Type)
	}
	raw, _ := json.Marshal(rec.Details)
	var d audit.DaemonDetails
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal DaemonDetails: %v", err)
	}
	if d.Version != "v0.3.1" {
		t.Errorf("Version: want v0.3.1, got %q", d.Version)
	}
	if len(d.PanicDigest) != 16 {
		t.Errorf("PanicDigest length: want 16, got %d (%q)", len(d.PanicDigest), d.PanicDigest)
	}
	// Raw stack trace must NOT appear in the audit record.
	if strings.Contains(buf.String(), "goroutine 1") {
		t.Error("raw stack trace must not appear in audit record")
	}
}

//  Logger: config.reload

func TestLogger_RecordConfigReload_RestartRequired(t *testing.T) {
	l, buf := captureLogger(t)

	changed := []string{"log_level", "prometheus.addr", "ai.api_key"}
	l.RecordConfigReload("/etc/kerno/config.yaml", "SIGHUP", changed, 1, 0)

	var rec audit.Record
	if err := json.NewDecoder(buf).Decode(&rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw, _ := json.Marshal(rec.Details)
	var d audit.ConfigReloadDetails
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal ConfigReloadDetails: %v", err)
	}
	if d.RestartRequired != 1 {
		t.Errorf("RestartRequired: want 1, got %d", d.RestartRequired)
	}
	if d.Applied != 2 { // 3 changed - 1 restart_required = 2 applied
		t.Errorf("Applied: want 2, got %d", d.Applied)
	}
	// Path must be redacted.
	if d.Path != "/etc/<redacted>" {
		t.Errorf("Path: want /etc/<redacted>, got %q", d.Path)
	}
}

// NEW: Verify that the actor field follows the "config/<source>" pattern
// for a "file" source (initial load), not just SIGHUP.
func TestLogger_RecordConfigReload_FileSource_Actor(t *testing.T) {
	l, buf := captureLogger(t)

	l.RecordConfigReload("/etc/kerno/config.yaml", "file", []string{"log_level"}, 0, 0)

	var rec audit.Record
	if err := json.NewDecoder(buf).Decode(&rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Actor != "config/file" {
		t.Errorf("Actor: want config/file, got %q", rec.Actor)
	}

	raw, _ := json.Marshal(rec.Details)
	var d audit.ConfigReloadDetails
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.Source != "file" {
		t.Errorf("Source: want file, got %q", d.Source)
	}
	if d.Applied != 1 {
		t.Errorf("Applied: want 1, got %d", d.Applied)
	}
}

//  Logger: NDJSON validity

func TestLogger_MultipleRecords_ValidNDJSON(t *testing.T) {
	l, buf := captureLogger(t)

	l.Record("kerno/start", audit.EventDaemonStart, audit.DaemonDetails{Version: "v0.1.0"})
	l.RecordBPFLoad("disk_io", true, nil)
	l.RecordAICall("openai", "gpt-4o-mini", 200, 500, 100, audit.RedactSummary{}, 300)

	dec := json.NewDecoder(buf)
	count := 0
	for dec.More() {
		var rec audit.Record
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("record %d: decode error: %v", count+1, err)
		}
		if rec.Type == "" {
			t.Errorf("record %d: Type must not be empty", count+1)
		}
		count++
	}
	if count != 3 {
		t.Errorf("want 3 NDJSON records, got %d", count)
	}
}

//  Logger: PII never reaches ai.call record

func TestLogger_NoPIIInAIRecord(t *testing.T) {
	l, buf := captureLogger(t)

	l.RecordAICall("anthropic", "claude-sonnet-4-20250514", 100, 500, 200,
		audit.RedactSummary{PIDs: 1, IPs: 2, Paths: 0}, 123)

	raw := buf.String()
	piiStrings := []string{"192.168.", "10.0.0.", "/etc/", "/home/", "pid="}
	for _, s := range piiStrings {
		if strings.Contains(raw, s) {
			t.Errorf("PII %q found in audit record: %q", s, raw)
		}
	}
}

//  Noop logger

func TestNoop_DoesNotPanic(t *testing.T) {
	l := audit.Noop()
	l.Record("actor", audit.EventDaemonStart, nil)
	l.RecordBPFLoad("prog", true, nil)
	l.RecordAICall("p", "m", 0, 0, 0, audit.RedactSummary{}, 0)
	l.RecordAuthFailure("/metrics", "token_mismatch", "")
	l.RecordFindingEmit("rule", "CRITICAL", "slack", "", "")
	l.RecordConfigReload("/etc/kerno/config.yaml", "SIGHUP", []string{"log_level"}, 0, 0)
	l.RecordPanic("v0.1.0", []byte("stack"))
}

//  RedactSummary.Total

func TestRedactSummary_Total(t *testing.T) {
	s := audit.RedactSummary{PIDs: 2, IPs: 3, Paths: 1}
	if s.Total() != 6 {
		t.Errorf("Total: want 6, got %d", s.Total())
	}
}

// End-to-end cycle linkage
//
// Verifies the full audit trail described in the schema doc:
//
//	bpf.load  (program loaded)
//	    ↓
//	ai.call   (analysis performed, same cycle window)
//	    ↓
//	finding.emit (finding dispatched, carrying cycle_id that links back to ai.call)
//
// The test checks that:
//  1. All three record types are emitted in order.
//  2. The finding.emit record carries the correct cycle_id.
//  3. The payload_hash is 16 hex chars (valid FNV-1a output).
//  4. No PII appears anywhere in the output.
func TestCycleLinkage_EndToEnd(t *testing.T) {
	l, buf := captureLogger(t)

	const cycleID = "cycle-20260510-143200"

	// Step 1: eBPF program loaded.
	l.RecordBPFLoad("syscall_latency", true, nil)

	// Step 2: AI call for this cycle.
	l.RecordAICall(
		"anthropic",
		"claude-sonnet-4-20250514",
		412,
		1024,
		380,
		audit.RedactSummary{PIDs: 3, IPs: 1, Paths: 0},
		854,
	)

	// Step 3: Finding emitted — carries the cycle_id linking back to the AI call.
	payloadHash := audit.HashPayload(`{"rule":"syscall_latency_critical","severity":"CRITICAL"}`)
	l.RecordFindingEmit("syscall_latency_critical", "CRITICAL", "slack", payloadHash, cycleID)

	// Decode all three NDJSON records.
	type rawRecord struct {
		Type    string          `json:"type"`
		Details json.RawMessage `json:"details"`
	}

	dec := json.NewDecoder(buf)
	var records []rawRecord
	for dec.More() {
		var r rawRecord
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("decode: %v", err)
		}
		records = append(records, r)
	}

	if len(records) != 3 {
		t.Fatalf("want 3 records, got %d", len(records))
	}

	// Record 0: bpf.load
	if records[0].Type != string(audit.EventBPFLoad) {
		t.Errorf("records[0].type: want bpf.load, got %q", records[0].Type)
	}
	var bpfD audit.BPFLoadDetails
	if err := json.Unmarshal(records[0].Details, &bpfD); err != nil {
		t.Fatalf("unmarshal BPFLoadDetails: %v", err)
	}
	if !bpfD.Success {
		t.Error("bpf.load success must be true")
	}
	if bpfD.Program != "syscall_latency" {
		t.Errorf("bpf.load program: want syscall_latency, got %q", bpfD.Program)
	}

	// Record 1: ai.call
	if records[1].Type != string(audit.EventAICall) {
		t.Errorf("records[1].type: want ai.call, got %q", records[1].Type)
	}
	var aiD audit.AICallDetails
	if err := json.Unmarshal(records[1].Details, &aiD); err != nil {
		t.Fatalf("unmarshal AICallDetails: %v", err)
	}
	if aiD.Tokens != 412 {
		t.Errorf("ai.call tokens: want 412, got %d", aiD.Tokens)
	}
	if aiD.Redactions.PIDs != 3 {
		t.Errorf("ai.call redactions.pid: want 3, got %d", aiD.Redactions.PIDs)
	}

	// Record 2: finding.emit — must carry the cycle_id
	if records[2].Type != string(audit.EventFindingEmit) {
		t.Errorf("records[2].type: want finding.emit, got %q", records[2].Type)
	}
	var fD audit.FindingEmitDetails
	if err := json.Unmarshal(records[2].Details, &fD); err != nil {
		t.Fatalf("unmarshal FindingEmitDetails: %v", err)
	}
	if fD.CycleID != cycleID {
		t.Errorf("finding.emit cycle_id: want %q, got %q", cycleID, fD.CycleID)
	}
	if len(fD.PayloadHash) != 16 {
		t.Errorf("finding.emit payload_hash length: want 16, got %d (%q)", len(fD.PayloadHash), fD.PayloadHash)
	}
	if fD.Severity != "CRITICAL" {
		t.Errorf("finding.emit severity: want CRITICAL, got %q", fD.Severity)
	}
	if fD.Sink != "slack" {
		t.Errorf("finding.emit sink: want slack, got %q", fD.Sink)
	}

	// No PII anywhere in the raw NDJSON output.
	raw := buf.String()
	for _, pii := range []string{"192.168.", "10.0.", "/etc/", "/home/", "pid="} {
		if strings.Contains(raw, pii) {
			t.Errorf("PII %q leaked into audit output", pii)
		}
	}
}

// helpers

type testError string

func (e testError) Error() string { return string(e) }
