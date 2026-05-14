// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// DiskScenario writes random data and fsyncs in a tight loop, driving
// disk write latency up. Pairs with the disk_io_bottleneck rule.
//
// To avoid filling the disk, the file is truncated periodically — only
// a small (~16 MB) working set is ever on disk.
type DiskScenario struct{}

func init() { Register(DiskScenario{}) }

// Name implements Scenario.
func (DiskScenario) Name() string { return "disk-sat" }

// Description implements Scenario.
func (DiskScenario) Description() string {
	return "Write+fsync in a tight loop to saturate block I/O latency"
}

// PairedRule implements Scenario.
func (DiskScenario) PairedRule() string { return "disk_io_bottleneck" }

// Run implements Scenario.
//
// Multiple parallel writers each fsync their own file. Because fsync is
// serialized at the disk driver, N concurrent fsyncers drive p99
// latency up by ~N× a single fsync — that's what kerno's
// disk_io_bottleneck rule keys on. A lone writer rarely crosses the
// 50 ms warning threshold on a modern SSD.
func (s DiskScenario) Run(ctx context.Context, opts Options) error {
	tmpDir, err := os.MkdirTemp("", "kerno-chaos-disk-")
	if err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	blockSize := blockSizeFromIntensity(opts.Intensity)
	writers := writersFromIntensity(opts.Intensity)

	block := make([]byte, blockSize)
	if _, err := rand.Read(block); err != nil {
		return fmt.Errorf("seed block: %w", err)
	}

	fmt.Fprintf(opts.Out, "    %d writers fsyncing %d-byte blocks into %s\n",
		writers, blockSize, tmpDir)

	var totalOps atomic.Uint64
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// path is constructed inside our own tmpDir; gosec G304 N/A.
			path := filepath.Join(tmpDir, fmt.Sprintf("w%d", idx))
			f, err := os.Create(path) //nolint:gosec // controlled tmp path
			if err != nil {
				return
			}
			defer func() { _ = f.Close() }()

			const truncateThreshold = 16 << 20
			var written int64
			for ctx.Err() == nil {
				n, err := f.Write(block)
				if err != nil {
					return
				}
				if err := f.Sync(); err != nil {
					return
				}
				totalOps.Add(1)
				written += int64(n)
				if written >= truncateThreshold {
					if err := f.Truncate(0); err != nil {
						return
					}
					if _, err := f.Seek(0, io.SeekStart); err != nil {
						return
					}
					written = 0
				}
			}
		}(i)
	}
	wg.Wait()

	fmt.Fprintf(opts.Out, "    completed %d write+fsync operations across %d writers\n",
		totalOps.Load(), writers)
	return nil
}

func blockSizeFromIntensity(intensity Intensity) int {
	switch intensity {
	case IntensityLow:
		return 4096
	case IntensityHigh:
		return 64 * 1024
	default:
		return 16 * 1024
	}
}

// writersFromIntensity controls how many goroutines fight for the disk.
// More writers = deeper kernel I/O queue = higher p99 latency.
func writersFromIntensity(intensity Intensity) int {
	switch intensity {
	case IntensityLow:
		return 4
	case IntensityHigh:
		return 32
	default:
		return 16
	}
}
