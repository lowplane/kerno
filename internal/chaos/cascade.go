// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CascadeScenario runs disk, TCP, memory, and CPU scenarios in sequence
// with overlap, simulating a real production incident: storage hiccup
// → upstream timeout cascade → memory pressure → final CPU contention
// as queues back up. Used as the headline GIF.
type CascadeScenario struct{}

func init() { Register(CascadeScenario{}) }

// Name implements Scenario.
func (CascadeScenario) Name() string { return "cascade" }

// Description implements Scenario.
func (CascadeScenario) Description() string {
	return "Disk → TCP → memory → CPU cascade simulating a real incident"
}

// PairedRule implements Scenario.
func (CascadeScenario) PairedRule() string { return "multiple" }

// Run implements Scenario.
func (s CascadeScenario) Run(ctx context.Context, opts Options) error {
	// Each stage gets ~1/3 of the duration and overlaps with the next.
	stageBudget := opts.Duration / 3
	if stageBudget <= 0 {
		stageBudget = 5 * time.Second
	}

	fmt.Fprintf(opts.Out, "    cascade: 4 stages × ~%s with overlap\n", stageBudget)

	var wg sync.WaitGroup
	launch := func(after time.Duration, runFor time.Duration, sub Scenario) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case <-time.After(after):
			}
			subCtx, cancel := context.WithTimeout(ctx, runFor)
			defer cancel()
			subOpts := opts
			subOpts.Duration = runFor
			fmt.Fprintf(opts.Out, "    [+%s] starting %s\n", after.Round(time.Second), sub.Name())
			if err := sub.Run(subCtx, subOpts); err != nil {
				fmt.Fprintf(opts.Out, "    [%s] error: %v\n", sub.Name(), err)
			}
		}()
	}

	launch(0, stageBudget*2, DiskScenario{})
	launch(stageBudget/2, stageBudget*2, TCPChurnScenario{})
	launch(stageBudget, stageBudget*2, MemoryScenario{})
	launch(stageBudget*2, stageBudget, CPUScenario{})

	wg.Wait()
	return nil
}
