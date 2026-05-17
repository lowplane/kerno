// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package auth provides HTTP middleware for securing Kerno daemon endpoints.
package auth

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
)

// BearerGuard is an HTTP middleware that validates Bearer tokens on protected
// endpoints. Tokens are compared in constant time to prevent timing
// side-channel attacks.
//
// The active token is stored under a RWMutex so it can be swapped at runtime
// (e.g. on SIGHUP) without blocking in-flight scrape requests.
type BearerGuard struct {
	mu     sync.RWMutex
	token  []byte // raw token bytes; nil means pass-through (no auth)
	logger *slog.Logger
}

// NewBearerGuard constructs a BearerGuard primed with the token read from
// tokenFile. If tokenFile is empty the guard operates in pass-through mode
// (no authentication enforced), which preserves existing behaviour for users
// who have not configured auth.
func NewBearerGuard(tokenFile string, logger *slog.Logger) (*BearerGuard, error) {
	g := &BearerGuard{logger: logger}
	if tokenFile == "" {
		return g, nil
	}
	if err := g.load(tokenFile); err != nil {
		return nil, fmt.Errorf("auth: loading bearer token from %q: %w", tokenFile, err)
	}
	return g, nil
}

// Reload re-reads the token from tokenFile and atomically swaps it in.
// Intended to be invoked from a SIGHUP handler; safe to call concurrently
// with active HTTP requests.
func (g *BearerGuard) Reload(tokenFile string) error {
	if err := g.load(tokenFile); err != nil {
		return fmt.Errorf("auth: reloading bearer token: %w", err)
	}
	g.logger.Info("bearer token reloaded", "file", tokenFile)
	return nil
}

// Wrap returns an http.Handler that enforces bearer token authentication
// before delegating to next. Callers should wrap only the /metrics handler;
// /healthz and /readyz must stay unauthenticated for kubelet probes.
func (g *BearerGuard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.RLock()
		want := g.token
		g.mu.RUnlock()

		// Pass-through: auth not configured.
		if want == nil {
			next.ServeHTTP(w, r)
			return
		}

		got := extractBearer(r.Header.Get("Authorization"))
		if got == "" {
			http.Error(w, "bearer token required", http.StatusUnauthorized)
			return
		}

		// Constant-time comparison prevents timing side-channel attacks.
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			g.logger.Warn("rejected /metrics request: invalid bearer token",
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// load reads, trims, and stores the token from path under write lock.
func (g *BearerGuard) load(path string) error {
	// #nosec G304 -- path comes from operator config
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return fmt.Errorf("token file %q is empty", path)
	}
	g.mu.Lock()
	g.token = []byte(tok)
	g.mu.Unlock()
	return nil
}

// extractBearer returns the token value from a "Bearer <token>" Authorization
// header. Returns an empty string if the header is absent or malformed.
func extractBearer(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}
