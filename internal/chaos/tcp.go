// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
)

// TCPChurnScenario opens a localhost TCP echo server and rapidly
// connects/closes against it from multiple workers, driving connection
// churn and ephemeral-port use. Pairs with the tcp_connection_churn
// or scheduler_contention rule (depends on what's most stressed).
type TCPChurnScenario struct{}

func init() { Register(TCPChurnScenario{}) }

// Name implements Scenario.
func (TCPChurnScenario) Name() string { return "tcp-churn" }

// Description implements Scenario.
func (TCPChurnScenario) Description() string {
	return "Open and close localhost TCP connections at high rate"
}

// PairedRule implements Scenario.
//
// Localhost connect/close storms don't induce retransmits or RTT spikes
// (loopback has near-zero latency), but they do drive scheduler pressure
// from rapid socket syscalls. That's what the doctor will flag.
func (TCPChurnScenario) PairedRule() string { return "scheduler_contention" }

// Run implements Scenario.
func (s TCPChurnScenario) Run(ctx context.Context, opts Options) error {
	lc := &net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	dialer := &net.Dialer{}

	// Server: accept loop drains each connection then closes it.
	var serverWG sync.WaitGroup
	serverWG.Add(1)
	go func() {
		defer serverWG.Done()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}(c)
		}
	}()

	// Stop the listener when the context expires so accept returns.
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	workers := workersFromIntensity(opts.Intensity, runtime.NumCPU())
	fmt.Fprintf(opts.Out, "    %d clients churning connections to %s\n", workers, addr)

	var (
		clientWG sync.WaitGroup
		count    uint64
		mu       sync.Mutex
	)
	for i := 0; i < workers; i++ {
		clientWG.Add(1)
		go func() {
			defer clientWG.Done()
			for ctx.Err() == nil {
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				if err != nil {
					if isShutdownErr(err) {
						return
					}
					continue
				}
				_ = conn.Close()
				mu.Lock()
				count++
				mu.Unlock()
			}
		}()
	}

	clientWG.Wait()
	serverWG.Wait()

	mu.Lock()
	total := count
	mu.Unlock()
	fmt.Fprintf(opts.Out, "    completed %d TCP connections\n", total)
	return nil
}

// isShutdownErr returns true when err is from a closed listener — those
// are normal exit conditions, not failures.
func isShutdownErr(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	return errors.Is(err, net.ErrClosed)
}
