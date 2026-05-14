// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// TCPLossScenario streams bulk TCP data over loopback so that any
// configured packet loss (e.g. via `tc qdisc add dev lo root netem
// loss 30%`) produces a heavy retransmit rate the doctor can detect.
//
// Pure tcp-churn on lo doesn't reliably trip the retransmit_storm rule
// — short connect/close exchanges only hit a handful of packets each
// and the SYN often succeeds first try. Bulk data forces hundreds of
// packets per connection; with any non-zero loss, retransmits become
// unavoidable.
type TCPLossScenario struct{}

func init() { Register(TCPLossScenario{}) }

// Name implements Scenario.
func (TCPLossScenario) Name() string { return "tcp-loss" }

// Description implements Scenario.
func (TCPLossScenario) Description() string {
	return "Stream bulk TCP data over loopback to expose any packet loss as retransmits"
}

// PairedRule implements Scenario.
func (TCPLossScenario) PairedRule() string { return "tcp_retransmit_storm" }

// Run implements Scenario.
//
// Pre-condition (caller responsibility): apply packet loss on lo via
//
//	sudo tc qdisc add dev lo root netem loss 30%
//
// without it, this scenario simply pumps healthy traffic and won't
// trip retransmit rules.
func (s TCPLossScenario) Run(ctx context.Context, opts Options) error {
	lc := &net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	// Server reads everything until EOF.
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
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	addr := listener.Addr().String()
	workers := loadersFromIntensity(opts.Intensity)
	bytesPerConn := bytesPerConnFromIntensity(opts.Intensity)

	// Pre-generate one random payload that all workers reuse.
	payload := make([]byte, bytesPerConn)
	if _, err := rand.Read(payload); err != nil {
		return fmt.Errorf("seed payload: %w", err)
	}

	fmt.Fprintf(opts.Out, "    %d streams × %d bytes each → %s (loss expected from lo qdisc)\n",
		workers, bytesPerConn, addr)

	var totalBytes atomic.Uint64
	var totalConns atomic.Uint64

	dialer := &net.Dialer{}
	var clientWG sync.WaitGroup
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
				n, _ := conn.Write(payload)
				_ = conn.Close()
				if n > 0 {
					totalBytes.Add(uint64(n)) //nolint:gosec // n>0 verified above
				}
				totalConns.Add(1)
			}
		}()
	}

	clientWG.Wait()
	serverWG.Wait()

	fmt.Fprintf(opts.Out, "    pumped %d bytes across %d connections\n",
		totalBytes.Load(), totalConns.Load())
	return nil
}

func loadersFromIntensity(intensity Intensity) int {
	switch intensity {
	case IntensityLow:
		return 4
	case IntensityHigh:
		return 24
	default:
		return 12
	}
}

func bytesPerConnFromIntensity(intensity Intensity) int {
	// Larger payloads per connection guarantee more in-flight packets,
	// so even a small loss probability still produces lots of retransmits.
	switch intensity {
	case IntensityLow:
		return 64 * 1024 // 64 KB
	case IntensityHigh:
		return 1 << 20 // 1 MB
	default:
		return 256 * 1024 // 256 KB
	}
}
