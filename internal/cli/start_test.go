// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthzHandlerOK(t *testing.T) {
	h := healthzHandler(6, 6)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v (body=%q)", err, rec.Body.String())
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %v, want ok", body["status"])
	}
}

func TestHealthzHandlerPartialLoad(t *testing.T) {
	// 4 of 6 loaders worked — endpoint should still be 200 (the daemon
	// is functional, just degraded), with the report reflecting it.
	h := healthzHandler(4, 6)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (graceful degradation)", rec.Code)
	}
}

func TestHealthzHandlerZeroLoaded(t *testing.T) {
	h := healthzHandler(0, 6)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	h(rec, req)
	// Currently the handler always returns 200 even with 0 loaded.
	// That's by design — the daemon can still serve metrics and the
	// signal is exposed via the JSON body. If the desired behavior
	// later becomes "fail readiness when 0 loaded", flip this assertion.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestReadyzHandlerPartialLoad(t *testing.T) {
	// Partial load is still considered ready because the daemon
	// supports graceful degradation.
	h := readyzHandler(4, 6)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/readyz",
		nil,
	)

	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	if body["status"] != "ready" {
		t.Errorf("status field = %v, want ready", body["status"])
	}
}

func TestReadyzHandlerZeroLoaded(t *testing.T) {
	h := readyzHandler(0, 6)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/readyz",
		nil,
	)

	h(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	if body["status"] != "not_ready" {
		t.Errorf("status field = %v, want not_ready", body["status"])
	}
}

func TestReadyzHandlerOK(t *testing.T) {
	h := readyzHandler(6, 6)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/readyz",
		nil,
	)

	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v (body=%q)", err, rec.Body.String())
	}

	if body["status"] != "ready" {
		t.Errorf("status field = %v, want ready", body["status"])
	}
}
