// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// CPUScenario saturates the host CPU by running tight loops on multiple
// goroutines. Pairs with the scheduler_contention rule (run-queue delay
// climbs once N > NumCPU).
type CPUScenario struct{}

func init() { Register(CPUScenario{}) }

// Name implements Scenario.
func (CPUScenario) Name() string { return "cpu" }

// Description implements Scenario.
func (CPUScenario) Description() string {
	return "Pin N goroutines on tight CPU loops to drive scheduler contention"
}

// PairedRule implements Scenario.
func (CPUScenario) PairedRule() string { return "scheduler_contention" }

// Run implements Scenario.
//
// Two kinds of workers run together:
//
//  1. Spinners: pinned to OS threads via runtime.LockOSThread, running
//     tight CPU loops. These saturate every CPU.
//
//  2. Wakers: ordinary goroutines that briefly sleep then do a small
//     burst of work. Sleep parks them on a futex; when the timer fires
//     they go through sched_wakeup. With every CPU saturated by the
//     spinners, they wait in the kernel runqueue before being scheduled
//     — which is exactly the signal kerno's sched_delay collector
//     measures (wakeup-to-switch interval).
//
// Without the wakers, pure spinners never sleep, so they never trigger
// sched_wakeup and the runqueue stays invisible to the doctor.
func (s CPUScenario) Run(ctx context.Context, opts Options) error {
	spinners := cpuWorkersFromIntensity(opts.Intensity, runtime.NumCPU())
	wakers := wakerCountFromIntensity(opts.Intensity, runtime.NumCPU())
	fmt.Fprintf(opts.Out, "    spawning %d CPU-pinned spinners + %d wakers (NumCPU=%d)\n",
		spinners, wakers, runtime.NumCPU())

	// sink is updated atomically across all workers so the compiler
	// can't prove the loop body is dead.
	var sink atomic.Uint64

	var wg sync.WaitGroup
	for i := 0; i < spinners; i++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			runtime.LockOSThread()
			// math/rand is fine here — we only need pseudo-random
			// floats to keep the optimizer from removing the loop.
			r := rand.New(rand.NewSource(seed)) //nolint:gosec
			for ctx.Err() == nil {
				var local float64
				for k := 0; k < 100_000 && ctx.Err() == nil; k++ {
					local += math.Sqrt(r.Float64())
				}
				sink.Add(uint64(local))
			}
		}(int64(i))
	}
	for i := 0; i < wakers; i++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			// Lock to a dedicated OS thread and sleep via the nanosleep
			// syscall. time.Sleep parks the goroutine inside Go's
			// runtime, which can resume it without going through the
			// kernel scheduler — sched_wakeup never fires. Direct
			// nanosleep guarantees the OS task transitions from
			// TASK_INTERRUPTIBLE → TASK_RUNNING, which is what
			// kerno's sched_delay collector measures.
			runtime.LockOSThread()
			r := rand.New(rand.NewSource(seed))          //nolint:gosec
			ts := unix.Timespec{Sec: 0, Nsec: 1_000_000} // 1 ms
			for ctx.Err() == nil {
				_ = unix.Nanosleep(&ts, nil)
				var local float64
				for k := 0; k < 5_000; k++ {
					local += math.Sqrt(r.Float64())
				}
				sink.Add(uint64(local))
			}
		}(int64(i + spinners))
	}
	wg.Wait()
	_ = sink.Load() // observe the running total to keep it live
	return nil
}

// wakerCountFromIntensity returns how many wake-and-work goroutines
// run alongside the spinners. They're the ones whose runqueue delay
// the doctor will catch.
func wakerCountFromIntensity(intensity Intensity, ncpu int) int {
	if ncpu <= 0 {
		ncpu = 1
	}
	switch intensity {
	case IntensityLow:
		return 4
	case IntensityHigh:
		return ncpu * 4
	default:
		return ncpu * 2
	}
}

// cpuWorkersFromIntensity oversubscribes CPUs heavily so the OS
// scheduler genuinely queues threads.
func cpuWorkersFromIntensity(intensity Intensity, ncpu int) int {
	if ncpu <= 0 {
		ncpu = 1
	}
	switch intensity {
	case IntensityLow:
		return ncpu * 2
	case IntensityHigh:
		return ncpu * 8
	default:
		return ncpu * 4
	}
}
