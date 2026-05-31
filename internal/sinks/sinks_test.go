package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/doctor"
)

func TestDeduper(t *testing.T) {
	d := NewDeduper(50 * time.Millisecond)

	f1 := doctor.Finding{Rule: "A", Severity: doctor.SeverityWarning, Process: "foo"}
	f2 := doctor.Finding{Rule: "B", Severity: doctor.SeverityCritical, Process: "bar"}

	// First pass: both novel
	novel := d.Filter([]doctor.Finding{f1, f2})
	if len(novel) != 2 {
		t.Fatalf("expected 2 novel findings, got %d", len(novel))
	}

	// Second pass immediately: both dropped
	novel = d.Filter([]doctor.Finding{f1, f2})
	if len(novel) != 0 {
		t.Fatalf("expected 0 novel findings (deduped), got %d", len(novel))
	}

	// Wait for TTL
	time.Sleep(60 * time.Millisecond)

	// Third pass: both novel again
	novel = d.Filter([]doctor.Finding{f1, f2})
	if len(novel) != 2 {
		t.Fatalf("expected 2 novel findings after TTL, got %d", len(novel))
	}
}

func TestSlackSink(t *testing.T) {
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewSlackSink(srv.URL, slog.Default())
	findings := []doctor.Finding{
		{
			Title:    "OOM Kill",
			Rule:     "oom",
			Severity: doctor.SeverityCritical,
			Process:  "postgres",
			Cause:    "out of memory",
			Impact:   "process killed",
			Fix:      []string{"increase limit"},
		},
	}

	err := sink.Send(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if body["text"] != "Kerno Diagnostic Findings" {
		t.Errorf("unexpected text in payload: %v", body["text"])
	}

	attachments, ok := body["attachments"].([]interface{})
	if !ok || len(attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %v", attachments)
	}
	
	att := attachments[0].(map[string]interface{})
	if att["color"] != "#e01e5a" {
		t.Errorf("expected critical color #e01e5a, got %v", att["color"])
	}
}

func TestPagerDutySink(t *testing.T) {
	var actions []string

	sink := NewPagerDutySink("dummy-key", slog.Default())

	// We override the URL in the sink to point to our test server
	// Note: since the URL is hardcoded in pagerduty.go, we would normally make it configurable.
	// For this test, we'll just test the Send loop with a mocked http.Client or RoundTripper.
	
	// Let's mock the RoundTripper to intercept the hardcoded URL.
	sink.client.Transport = &mockTransport{
		fn: func(req *http.Request) (*http.Response, error) {
			var payload map[string]interface{}
			json.NewDecoder(req.Body).Decode(&payload)
			actions = append(actions, payload["event_action"].(string))
			return &http.Response{StatusCode: 202, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		},
	}

	f1 := doctor.Finding{Rule: "rule1", Severity: doctor.SeverityWarning}
	
	// Cycle 1: trigger
	err := sink.Send(context.Background(), []doctor.Finding{f1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(actions) != 1 || actions[0] != "trigger" {
		t.Fatalf("expected 1 trigger, got %v", actions)
	}

	// Cycle 2: same finding, should trigger again (PD natively dedups triggers)
	actions = nil
	err = sink.Send(context.Background(), []doctor.Finding{f1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 || actions[0] != "trigger" {
		t.Fatalf("expected 1 trigger, got %v", actions)
	}

	// Cycle 3: finding clears (empty list) -> should resolve
	actions = nil
	err = sink.Send(context.Background(), []doctor.Finding{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 || actions[0] != "resolve" {
		t.Fatalf("expected 1 resolve, got %v", actions)
	}
}

func TestRetryBackoff(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), "POST", srv.URL, nil)
	err := sendWithRetry(context.Background(), srv.Client(), req, "test")

	if err == nil {
		t.Fatal("expected error after retries, got nil")
	}

	if atomic.LoadInt32(&calls) != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

type mockTransport struct {
	fn func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.fn(req)
}
