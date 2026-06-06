// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// FDLeakScenario opens new file descriptors at a steady rate without
// closing them, simulating a file descriptor leak. Pairs with the
// fd_leak rule.
type FDLeakScenario struct{}

func init() { Register(FDLeakScenario{}) }

// Name implements Scenario.
func (FDLeakScenario) Name() string { return "fd-leak" }

// Description implements Scenario.
func (FDLeakScenario) Description() string {
	return "Open file descriptors at a steady rate without closing them"
}

// PairedRule implements Scenario.
func (FDLeakScenario) PairedRule() string { return "fd_leak" }

// Run implements Scenario.
func (s FDLeakScenario) Run(ctx context.Context, opts Options) error {
	tmpDir, err := os.MkdirTemp("", "kerno-chaos-fd-")
	if err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	rate := fdRateFromIntensity(opts.Intensity)
	fmt.Fprintf(opts.Out, "    opening ~%d FDs/sec into %s\n", rate, tmpDir)

	var leaked []*os.File
	defer func() {
		for _, f := range leaked {
			_ = f.Close()
		}
		_ = os.RemoveAll(tmpDir)
	}()

	ticker := time.NewTicker(time.Second / time.Duration(rate))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(opts.Out, "    leaked %d file descriptors before exit (cleaned up)\n", len(leaked))
			return nil
		case <-ticker.C:
			f, err := os.CreateTemp(tmpDir, "leak-")
			if err != nil {
				if isResourceExhausted(err) {
					fmt.Fprintf(opts.Out, "    hit FD/inode limit at %d open files — stopping early\n", len(leaked))
					return nil
				}
				return fmt.Errorf("open: %w", err)
			}
			leaked = append(leaked, f)
		}
	}
}

func fdRateFromIntensity(intensity Intensity) int {
	switch intensity {
	case IntensityLow:
		return 50
	case IntensityHigh:
		return 500
	default:
		return 200
	}
}

// isResourceExhausted detects EMFILE / ENFILE / ENOSPC so the scenario
// can stop gracefully rather than treating ulimit-hits as fatal errors.
func isResourceExhausted(err error) bool {
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOSPC)
}
