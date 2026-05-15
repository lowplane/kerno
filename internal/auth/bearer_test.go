// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/optiqor/kerno/internal/auth"
)

// nopLogger discards all log output during tests.
var nopLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// writeTokenFile creates a temporary token file and returns its path.
func writeTokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "metrics-token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o400); err != nil {
		t.Fatalf("writing token file: %v", err)
	}
	return path
}

// okHandler is a trivial upstream that always returns 200 OK.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestBearerGuard_ValidToken(t *testing.T) {
	path := writeTokenFile(t, "supersecret")
	guard, err := auth.NewBearerGuard(path, nopLogger)
	if err != nil {
		t.Fatalf("NewBearerGuard: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer supersecret")
	w := httptest.NewRecorder()

	guard.Wrap(okHandler()).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("valid token: expected 200, got %d", w.Code)
	}
}

func TestBearerGuard_MissingAuthHeader(t *testing.T) {
	path := writeTokenFile(t, "supersecret")
	guard, err := auth.NewBearerGuard(path, nopLogger)
	if err != nil {
		t.Fatalf("NewBearerGuard: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()

	guard.Wrap(okHandler()).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing token: expected 401, got %d", w.Code)
	}
}

func TestBearerGuard_WrongToken(t *testing.T) {
	path := writeTokenFile(t, "correct")
	guard, err := auth.NewBearerGuard(path, nopLogger)
	if err != nil {
		t.Fatalf("NewBearerGuard: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()

	guard.Wrap(okHandler()).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: expected 401, got %d", w.Code)
	}
}

func TestBearerGuard_PassThrough_NoConfig(t *testing.T) {
	// Empty tokenFile → pass-through mode, no auth enforced.
	guard, err := auth.NewBearerGuard("", nopLogger)
	if err != nil {
		t.Fatalf("NewBearerGuard: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()

	guard.Wrap(okHandler()).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("pass-through: expected 200, got %d", w.Code)
	}
}

func TestBearerGuard_Reload(t *testing.T) {
	path := writeTokenFile(t, "old-token")
	guard, err := auth.NewBearerGuard(path, nopLogger)
	if err != nil {
		t.Fatalf("NewBearerGuard: %v", err)
	}

	// Rotate the token on disk and reload.
	if err := os.WriteFile(path, []byte("new-token\n"), 0o400); err != nil {
		t.Fatalf("rotating token file: %v", err)
	}
	if err := guard.Reload(path); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Old token must be rejected after reload.
	reqOld := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqOld.Header.Set("Authorization", "Bearer old-token")
	wOld := httptest.NewRecorder()
	guard.Wrap(okHandler()).ServeHTTP(wOld, reqOld)
	if wOld.Code != http.StatusUnauthorized {
		t.Errorf("old token after reload: expected 401, got %d", wOld.Code)
	}

	// New token must be accepted.
	reqNew := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqNew.Header.Set("Authorization", "Bearer new-token")
	wNew := httptest.NewRecorder()
	guard.Wrap(okHandler()).ServeHTTP(wNew, reqNew)
	if wNew.Code != http.StatusOK {
		t.Errorf("new token after reload: expected 200, got %d", wNew.Code)
	}
}

func TestBearerGuard_EmptyTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-token")
	if err := os.WriteFile(path, []byte("  \n"), 0o400); err != nil {
		t.Fatalf("writing empty token file: %v", err)
	}

	_, err := auth.NewBearerGuard(path, nopLogger)
	if err == nil {
		t.Error("expected error for empty token file, got nil")
	}
}
