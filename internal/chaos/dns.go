// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package chaos

import (
"context"
"fmt"
"net"
"runtime"
"sync"
"sync/atomic"
)

// DNSFloodScenario fires N DNS lookups per second against the local resolver
// (127.0.0.53 or systemd-resolved) to drive dns_high_latency and
// dns_failure_rate doctor rules.
type DNSFloodScenario struct{}

func init() { Register(DNSFloodScenario{}) }

// Name implements Scenario.
func (DNSFloodScenario) Name() string { return "dns-flood" }

// Description implements Scenario.
func (DNSFloodScenario) Description() string {
return "Fire DNS lookups at high rate to stress CoreDNS and trigger DNS doctor rules"
}

// PairedRule implements Scenario.
func (DNSFloodScenario) PairedRule() string { return "dns_high_latency" }

// Run implements Scenario.
func (s DNSFloodScenario) Run(ctx context.Context, opts Options) error {
workers := workersFromIntensity(opts.Intensity, runtime.NumCPU())

// Domains to resolve — mix of real and synthetic to stress the resolver.
domains := []string{
"kubernetes.default.svc.cluster.local.",
"kube-dns.kube-system.svc.cluster.local.",
"google.com.",
"nonexistent-host-kerno-chaos.local.",
"another-fake-host-kerno.cluster.local.",
}

resolver := &net.Resolver{
PreferGo: true,
Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
d := net.Dialer{}
// Try local resolver first; fall back to 8.8.8.8 for bare-metal.
conn, err := d.DialContext(ctx, "udp", "127.0.0.53:53")
if err != nil {
conn, err = d.DialContext(ctx, "udp", "8.8.8.8:53")
}
return conn, err
},
}

var (
wg      sync.WaitGroup
total   atomic.Uint64
errCnt  atomic.Uint64
)

fmt.Fprintf(opts.Out, "    %d workers flooding DNS lookups\n", workers)

for i := 0; i < workers; i++ {
wg.Add(1)
go func(workerID int) {
defer wg.Done()
idx := workerID % len(domains)
for ctx.Err() == nil {
domain := domains[idx%len(domains)]
idx++
_, err := resolver.LookupHost(ctx, domain)
total.Add(1)
if err != nil && ctx.Err() == nil {
errCnt.Add(1)
}
}
}(i)
}

wg.Wait()
fmt.Fprintf(opts.Out, "    completed %d DNS lookups (%d errors)\n",
total.Load(), errCnt.Load())
return nil
}
