// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Bpf-verify is a standalone test harness that loads each Kerno eBPF
// program into the kernel verifier and reports the result. Run with
// sudo (or with CAP_BPF + CAP_PERFMON granted to the binary).
//
//	go build -o bin/bpf-verify ./cmd/bpf-verify
//	sudo ./bin/bpf-verify             # Loads all 6 programs
//	sudo ./bin/bpf-verify --read 5s   # Then read events for 5 seconds
//
// On success, prints "VERIFIER OK" for each program and exits 0. On
// failure, prints the kernel verifier log so the eBPF C source can be
// fixed before shipping.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/optiqor/kerno/internal/bpf"
)

func main() {
	readWindow := flag.Duration("read", 0, "after loading, read events for this long (0 = skip)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	loaders := []bpf.Loader{
		bpf.NewSyscallLatencyLoader(logger),
		bpf.NewTCPMonitorLoader(logger),
		bpf.NewOOMTrackLoader(logger),
		bpf.NewDiskIOLoader(logger),
		bpf.NewSchedDelayLoader(logger),
		bpf.NewFDTrackLoader(logger),
	}

	closers := make([]io.Closer, 0, len(loaders))
	defer func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}()

	var loaded, failed int
	for _, l := range loaders {
		fmt.Printf("==> loading %s...\n", l.Name())
		closer, err := l.Load()
		if err != nil {
			failed++
			fmt.Printf("    LOAD FAILED: %v\n", err)
			continue
		}
		closers = append(closers, closer)
		loaded++
		fmt.Printf("    VERIFIER OK\n")
	}

	fmt.Println()
	fmt.Printf("Result: %d/%d programs loaded successfully\n", loaded, len(loaders))

	if loaded == 0 {
		// Run cleanup before exit; defer would not fire after os.Exit.
		for _, c := range closers {
			_ = c.Close()
		}
		closers = nil

		fmt.Fprintln(os.Stderr, "\nHints:")
		fmt.Fprintln(os.Stderr, "  - Re-run with sudo (CAP_BPF + CAP_PERFMON required)")
		fmt.Fprintln(os.Stderr, "  - Verify /sys/kernel/btf/vmlinux exists (kernel >= 5.8 with BTF)")
		fmt.Fprintln(os.Stderr, "  - Run 'make generate' if *_bpfel.go files are missing")
		os.Exit(1) //nolint:gocritic // closers already drained above
	}

	if *readWindow <= 0 {
		return
	}

	// Optional: stream events from each loaded program for a window so
	// the user can confirm tracepoints actually fire.
	fmt.Printf("\n==> reading events for %s (Ctrl+C to stop early)...\n\n", *readWindow)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancel2 := context.WithTimeout(ctx, *readWindow)
	defer cancel2()

	var counts [6]atomic.Uint64
	for i, l := range loaders {
		if i >= len(closers) {
			break
		}
		ch, err := l.Events(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    %s: events unavailable: %v\n", l.Name(), err)
			continue
		}
		go func(i int, ch <-chan bpf.RawEvent) {
			for {
				select {
				case <-ctx.Done():
					return
				case _, ok := <-ch:
					if !ok {
						return
					}
					counts[i].Add(1)
				}
			}
		}(i, ch)
	}

	<-ctx.Done()

	fmt.Println("\n==> events received per program:")
	for i, l := range loaders {
		if i >= len(closers) {
			fmt.Printf("  %-20s (not loaded)\n", l.Name())
			continue
		}
		fmt.Printf("  %-20s %d\n", l.Name(), counts[i].Load())
	}
}
