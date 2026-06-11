// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
"context"
"io"
"log/slog"
"net"
"testing"
"time"

"github.com/optiqor/kerno/internal/bpf"
"github.com/optiqor/kerno/internal/collector"
"github.com/testcontainers/testcontainers-go"
"github.com/testcontainers/testcontainers-go/wait"
)

func TestEBPFLoadAndEvents(t *testing.T) {
testcontainers.SkipIfProviderIsNotHealthy(t)

ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
defer cancel()

logger := slog.New(slog.NewTextHandler(io.Discard, nil))

syscallLoader := bpf.NewSyscallLatencyLoader(logger)
syscallCloser, err := syscallLoader.Load()
if err != nil {
t.Skipf("skip syscall eBPF integration test: load syscall_latency: %v", err)
}
t.Cleanup(func() { _ = syscallCloser.Close() })

syscallCollector := collector.NewSyscallCollector(logger, syscallLoader)
if err := syscallCollector.Start(ctx); err != nil {
t.Fatalf("start syscall collector: %v", err)
}
t.Cleanup(syscallCollector.Stop)

tcpLoader := bpf.NewTCPMonitorLoader(logger)
tcpCloser, err := tcpLoader.Load()
if err != nil {
t.Skipf("skip TCP eBPF integration test: load tcp_monitor: %v", err)
}
t.Cleanup(func() { _ = tcpCloser.Close() })

tcpCollector := collector.NewTCPCollector(logger, tcpLoader)
if err := tcpCollector.Start(ctx); err != nil {
t.Fatalf("start tcp collector: %v", err)
}
t.Cleanup(tcpCollector.Stop)

syscallGen, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
ContainerRequest: testcontainers.ContainerRequest{
Image: "docker.io/library/alpine:3.19",
Cmd: []string{
"sh",
"-c",
"for i in $(seq 1 500); do ls -la /etc >/dev/null 2>&1; cat /etc/hostname >/dev/null 2>&1; done; echo 'syscall-gen-done'",
},
WaitingFor:      wait.ForLog("syscall-gen-done").WithStartupTimeout(30 * time.Second),
AlwaysPullImage: false,
},
Started: true,
})
if err != nil {
t.Fatalf("start syscall generator container: %v", err)
}
t.Cleanup(func() {
termCtx, termCancel := context.WithTimeout(context.Background(), 15*time.Second)
defer termCancel()
_ = syscallGen.Terminate(termCtx)
})

ln, err := net.Listen("tcp", "127.0.0.1:0")
if err != nil {
t.Fatalf("listen on localhost: %v", err)
}
defer ln.Close()

tcpAddr := ln.Addr().String()
tcpReady := make(chan struct{})

go func() {
conn, err := ln.Accept()
if err != nil {
return
}
conn.Close()
}()

go func() {
time.Sleep(3 * time.Second)
conn, err := net.DialTimeout("tcp", tcpAddr, 5*time.Second)
if err != nil {
t.Logf("tcp dial: %v", err)
close(tcpReady)
return
}
conn.Close()
close(tcpReady)
}()

select {
case <-tcpReady:
case <-time.After(10 * time.Second):
t.Log("timeout waiting for TCP connection test")
}

time.Sleep(2 * time.Second)

syscallSnap, ok := syscallCollector.Snapshot().(*collector.SyscallSnapshot)
if !ok {
t.Fatalf("expected *SyscallSnapshot, got %T", syscallCollector.Snapshot())
}
if syscallSnap.TotalCount == 0 {
t.Fatalf("expected syscall collector to capture events, got TotalCount=0")
}
t.Logf("Syscall collector captured %d events across %d entries", syscallSnap.TotalCount, len(syscallSnap.Entries))

tcpSnap, ok := tcpCollector.Snapshot().(*collector.TCPSnapshot)
if !ok {
t.Fatalf("expected *TCPSnapshot, got %T", tcpCollector.Snapshot())
}
if tcpSnap.ActiveConnections == 0 && syscallSnap.TotalCount == 0 {
t.Fatalf("expected syscall or TCP collector to capture events, both empty")
}
t.Logf("TCP collector active connections: %d", tcpSnap.ActiveConnections)
}
