//go:build linux

// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
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

// TestRebindPrometheus_AddrChange verifies that rebindPrometheus correctly
// stops the old server and starts a new one on a different address —
// without using the --prometheus-addr CLI flag, which would pin the address
// and bypass the rebind path entirely.
//
// This is the exact scenario the reviewer flagged as untested:
// "worth a test that changes addr without the flag".
func TestRebindPrometheus_AddrChange(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Pick two free ports. We listen-then-close to reserve them;
	// there is a tiny TOCTOU window but it is acceptable in tests.
	addr1 := freeAddr(t)
	addr2 := freeAddr(t)

	var srvPtr atomic.Pointer[http.Server]

	// Start the initial server on addr1.
	srv1 := buildHTTPServer(addr1, 6, 6)
	go func() { _ = srv1.ListenAndServe() }()
	waitReady(t, addr1)
	srvPtr.Store(srv1)

	// Verify addr1 is serving before the rebind.
	if err := checkHTTP("http://" + addr1 + "/healthz"); err != nil {
		t.Fatalf("addr1 not serving before rebind: %v", err)
	}

	// Rebind to addr2 — no CLI flag involved.
	rebindPrometheus(logger, &srvPtr, addr2, 6, 6, true)

	// addr2 must now be serving.
	if err := checkHTTP("http://" + addr2 + "/healthz"); err != nil {
		t.Errorf("addr2 not serving after rebind: %v", err)
	}

	// addr1 must be shut down.
	if err := checkHTTP("http://" + addr1 + "/healthz"); err == nil {
		t.Errorf("addr1 still serving after rebind — old server not shut down")
	}

	// Cleanup.
	if srv := srvPtr.Load(); srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// TestRebindPrometheus_Disable verifies that passing enabled=false stops the
// running server and sets srvPtr to nil.
func TestRebindPrometheus_Disable(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	addr := freeAddr(t)

	var srvPtr atomic.Pointer[http.Server]

	srv := buildHTTPServer(addr, 6, 6)
	go func() { _ = srv.ListenAndServe() }()
	waitReady(t, addr)
	srvPtr.Store(srv)

	// Disable prometheus — enabled=false.
	rebindPrometheus(logger, &srvPtr, addr, 6, 6, false)

	// srvPtr must be nil after disable.
	if srvPtr.Load() != nil {
		t.Error("srvPtr should be nil after disabling prometheus")
	}

	// Server must no longer respond.
	if err := checkHTTP("http://" + addr + "/healthz"); err == nil {
		t.Error("server still responding after disable — not shut down")
	}
}

// TestRebindPrometheus_BindFail verifies that when the new address is already
// in use, rebindPrometheus surfaces the failure by setting srvPtr to nil
// rather than storing a dead *http.Server.
//
// This covers the reviewer's concern: "surfacing a failed rebind rather than
// swallowing it."
func TestRebindPrometheus_BindFail(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Hold a listener on the target address so the rebind bind fails fast.
	blocker, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blocker: %v", err)
	}
	defer blocker.Close()
	blockedAddr := blocker.Addr().String()

	var srvPtr atomic.Pointer[http.Server]
	// srvPtr starts nil — no previous server to shut down.

	rebindPrometheus(logger, &srvPtr, blockedAddr, 6, 6, true)

	// Bind must have failed; srvPtr must be nil — not a dead server.
	if got := srvPtr.Load(); got != nil {
		t.Error("srvPtr should be nil after a failed rebind — dead server must not be stored")
		// Cleanup to avoid leaking the goroutine.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = got.Shutdown(ctx)
	}
}

// freeAddr picks a free TCP address on loopback and returns it as "host:port".
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeAddr: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// waitReady polls addr until the TCP port accepts connections or the test
// deadline is exceeded. Used to avoid a fixed sleep after starting a server.
func waitReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := (&net.Dialer{Timeout: 50 * time.Millisecond}).DialContext(context.Background(), "tcp", addr)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server on %s did not become ready within 2s", addr)
}

// checkHTTP does a single GET and returns nil only on HTTP 200.
func checkHTTP(url string) error {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(url) //nolint:noctx // test helper, context not needed
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
