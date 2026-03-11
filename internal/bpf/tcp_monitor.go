// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I c/headers" -target bpfel -type tcp_event tcpMonitor c/tcp_monitor.c

// TCPMonitorLoader manages the tcp_monitor eBPF program.
type TCPMonitorLoader struct {
	logger *slog.Logger
	objs   *tcpMonitorObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// NewTCPMonitorLoader creates a new loader.
func NewTCPMonitorLoader(logger *slog.Logger) *TCPMonitorLoader {
	return &TCPMonitorLoader{
		logger: logger.With("loader", "tcp_monitor"),
	}
}

// Name implements Loader.
func (l *TCPMonitorLoader) Name() string {
	return "tcp_monitor"
}

// Load implements Loader.
func (l *TCPMonitorLoader) Load() (io.Closer, error) {
	l.objs = &tcpMonitorObjects{}
	if err := loadTcpMonitorObjects(l.objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	// Attach tracepoint/tcp/tcp_retransmit_skb.
	retransLink, err := link.Tracepoint("tcp", "tcp_retransmit_skb", l.objs.TracepointTcpRetransmit, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching tcp_retransmit_skb tracepoint: %w", err)
	}
	l.links = append(l.links, retransLink)

	// Attach tracepoint/sock/inet_sock_set_state.
	stateLink, err := link.Tracepoint("sock", "inet_sock_set_state", l.objs.TracepointInetSockSetState, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching inet_sock_set_state tracepoint: %w", err)
	}
	l.links = append(l.links, stateLink)

	// Open ring buffer reader.
	reader, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	l.reader = reader

	l.logger.Info("tcp_monitor eBPF program loaded and attached")

	return closerFunc(l.close), nil
}

// Events implements Loader.
func (l *TCPMonitorLoader) Events(ctx context.Context) (<-chan RawEvent, error) {
	if l.reader == nil {
		return nil, fmt.Errorf("loader not loaded; call Load() first")
	}

	ch := make(chan RawEvent, 256)
	go l.readLoop(ctx, ch)
	return ch, nil
}

func (l *TCPMonitorLoader) readLoop(ctx context.Context, ch chan<- RawEvent) {
	defer close(ch)

	for {
		record, err := l.reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			l.logger.Warn("error reading ring buffer", "error", err)
			return
		}

		select {
		case <-ctx.Done():
			return
		case ch <- RawEvent{
			Type: EventTCPMonitor,
			Data: bytes.Clone(record.RawSample),
		}:
		}
	}
}

func (l *TCPMonitorLoader) close() {
	if l.reader != nil {
		l.reader.Close()
		l.reader = nil
	}
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.links = nil
	if l.objs != nil {
		l.objs.Close()
		l.objs = nil
	}
}

// DecodeTCPEvent decodes a raw event into a typed TCPEvent.
func DecodeTCPEvent(data []byte) (*TCPEvent, error) {
	var event TCPEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding tcp event: %w", err)
	}
	return &event, nil
}
