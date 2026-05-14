// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package chaos provides synthetic failure injectors used by demos,
// the README screencasts, and CI rule-firing tests. Every scenario
// here pairs with at least one doctor rule so the end-to-end story
// "induce → detect → explain" stays exercised over time.
//
// All scenarios are entirely in-process: no external tools are
// invoked, no system files modified outside /tmp, no network beyond
// loopback. Each scenario runs until its context is canceled.
package chaos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// Intensity controls how aggressive a scenario is.
type Intensity int

const (
	IntensityLow Intensity = iota
	IntensityMedium
	IntensityHigh
)

// String returns the human-readable intensity name.
func (i Intensity) String() string {
	switch i {
	case IntensityLow:
		return "low"
	case IntensityMedium:
		return "medium"
	case IntensityHigh:
		return "high"
	default:
		return fmt.Sprintf("intensity(%d)", int(i))
	}
}

// ParseIntensity parses a human string into an Intensity. Empty or
// unrecognized strings default to Medium.
func ParseIntensity(s string) Intensity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low", "l":
		return IntensityLow
	case "high", "h":
		return IntensityHigh
	default:
		return IntensityMedium
	}
}

// Options is the runtime configuration passed to every scenario.
type Options struct {
	Intensity Intensity
	Duration  time.Duration
	Logger    *slog.Logger
	// Out receives status lines (defaults to discard if nil).
	Out io.Writer
}

// Scenario is one synthetic failure pattern. Implementations must
// honor ctx — Run must return when the context is canceled.
type Scenario interface {
	// Name returns a stable identifier (e.g., "cpu", "fd-leak").
	Name() string

	// Description is a one-line user-facing explanation.
	Description() string

	// PairedRule is the doctor rule that should fire when the scenario
	// is induced. Used by integration tests.
	PairedRule() string

	// Run executes the scenario until ctx is canceled.
	Run(ctx context.Context, opts Options) error
}

// ─── Registry ──────────────────────────────────────────────────────────────

var (
	registryMu sync.RWMutex
	registry   = map[string]Scenario{}
)

// Register adds a scenario. Panics on duplicate name (program error).
func Register(s Scenario) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[s.Name()]; exists {
		panic(fmt.Sprintf("chaos: scenario %q already registered", s.Name()))
	}
	registry[s.Name()] = s
}

// Get returns the scenario with the given name (or false).
func Get(name string) (Scenario, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	s, ok := registry[name]
	return s, ok
}

// List returns all registered scenarios sorted by name.
func List() []Scenario {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Scenario, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Reset clears the registry. Used by tests; not part of the public API
// in spirit even though it must be exported across packages.
func Reset() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = map[string]Scenario{}
}

// ─── Run helpers ───────────────────────────────────────────────────────────

// ErrNotFound is returned by Run when the named scenario does not exist.
var ErrNotFound = errors.New("chaos scenario not found")

// Run looks up a scenario and executes it for the configured duration,
// then returns. Cancellation of the parent context terminates early.
func Run(ctx context.Context, name string, opts Options) error {
	s, ok := Get(name)
	if !ok {
		return fmt.Errorf("%w: %q (try 'kerno chaos --list')", ErrNotFound, name)
	}

	if opts.Duration <= 0 {
		opts.Duration = 30 * time.Second
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	runCtx, cancel := context.WithTimeout(ctx, opts.Duration)
	defer cancel()

	fmt.Fprintf(opts.Out, "==> chaos: inducing %s (intensity=%s, duration=%s)\n",
		s.Name(), opts.Intensity, opts.Duration)
	fmt.Fprintf(opts.Out, "    rule expected to fire: %s\n", s.PairedRule())

	start := time.Now()
	err := s.Run(runCtx, opts)
	elapsed := time.Since(start).Round(time.Millisecond)

	// Context-canceled exits are normal for a duration-bounded run.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		err = nil
	}

	fmt.Fprintf(opts.Out, "==> chaos: %s finished in %s\n", s.Name(), elapsed)
	return err
}

// workersFromIntensity returns a sensible worker count for CPU-bound
// scenarios. Capped to NumCPU to avoid runaway goroutine churn.
func workersFromIntensity(intensity Intensity, ncpu int) int {
	if ncpu <= 0 {
		ncpu = 1
	}
	switch intensity {
	case IntensityLow:
		return max1(ncpu / 2)
	case IntensityHigh:
		return ncpu * 2
	default:
		return ncpu
	}
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
