// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package observability provides shared panic handling and crash-loop safety utilities.
package observability

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"
)

var (
	panicLogDir       = getPanicLogDir()
	crashLoopWindow   = 10 * time.Minute
	crashLoopMaxCount = 5
)

func getPanicLogDir() string {
	if dir := os.Getenv("KERNO_PANIC_LOG_DIR"); dir != "" {
		return dir
	}
	return "" // Empty string means disable file logging
}

// PanicHandler tracks panics and enforces crash-loop safety.
type PanicHandler struct {
	mu          sync.Mutex
	panicCounts map[string][]time.Time
}

// GlobalHandler is the shared instance of PanicHandler.
var GlobalHandler = &PanicHandler{
	panicCounts: make(map[string][]time.Time),
}

// HandlePanic processes a recovered panic. It writes the stack trace to a file
// (if logging is enabled), logs the error, and returns whether the collector should
// be permanently disabled due to crash-looping.
//
// Note: There is no cap or rotation on panic logs. The operator is responsible
// for managing disk space in the panic log directory.
func (h *PanicHandler) HandlePanic(component string, r any, logger *slog.Logger) bool {
	now := time.Now()

	// Determine panic reason
	reason := "unknown"
	if err, ok := r.(error); ok {
		reason = err.Error()
	} else if s, ok := r.(string); ok {
		reason = s
	}

	// Write stack trace to a file if logging is enabled
	if panicLogDir != "" {
		// Create panic log directory if it doesn't exist
		if err := os.MkdirAll(panicLogDir, 0750); err != nil {
			logger.Error("failed to create panic log directory", "dir", panicLogDir, "error", err)
		} else {
			stack := debug.Stack()
			filename := fmt.Sprintf("%s-%d.txt", component, now.Unix())
			path := filepath.Join(panicLogDir, filename)

			content := fmt.Sprintf("Time: %s\nComponent: %s\nPanic: %v\n\nStack:\n%s\n", now.Format(time.RFC3339), component, r, stack)
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				logger.Error("failed to write panic log", "path", path, "error", err)
			}

			logger.Error("recovered from panic",
				"component", component,
				"reason", reason,
				"log_file", path)
		}
	} else {
		// Log to stdout/stderr only when file logging is disabled
		logger.Error("recovered from panic",
			"component", component,
			"reason", reason,
			"stack", string(debug.Stack()))
	}

	// Check crash loop
	h.mu.Lock()
	defer h.mu.Unlock()

	timestamps := h.panicCounts[component]

	// Filter old timestamps
	var recent []time.Time
	for _, t := range timestamps {
		if now.Sub(t) <= crashLoopWindow {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	h.panicCounts[component] = recent

	if len(recent) >= crashLoopMaxCount {
		return true // Disable the component
	}

	return false
}

// HandleDaemonPanic processes a daemon-level panic.
// It writes the panic stack to a file and logs it.
func HandleDaemonPanic(r any, logger *slog.Logger) {
	GlobalHandler.HandlePanic("daemon", r, logger)
}
