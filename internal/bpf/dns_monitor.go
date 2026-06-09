//go:build ebpf

// Copyright 2026 Optiqor contributors
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86 -I c/headers" -target bpfel -type dns_event dnsMonitor c/dns_monitor.c

// DNSMonitorLoader manages the dns_monitor eBPF program.
type DNSMonitorLoader struct {
	logger *slog.Logger
	objs   *dnsMonitorObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// NewDNSMonitorLoader creates a new loader.
func NewDNSMonitorLoader(logger *slog.Logger) *DNSMonitorLoader {
	return &DNSMonitorLoader{
		logger: logger.With("loader", "dns_monitor"),
	}
}

// Name implements Loader.
func (l *DNSMonitorLoader) Name() string { return "dns_monitor" }

// Load implements Loader.
func (l *DNSMonitorLoader) Load() (io.Closer, error) {
	l.objs = &dnsMonitorObjects{}
	if err := loadDnsMonitorObjects(l.objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("loading dns_monitor objects: %w", err)
	}

	// Attach tracepoint/syscalls/sys_enter_sendmsg.
	sendLink, err := link.Tracepoint("syscalls", "sys_enter_sendmsg",
		l.objs.TracepointSysEnterSendmsg, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching sys_enter_sendmsg: %w", err)
	}
	l.links = append(l.links, sendLink)

	// Attach tracepoint/syscalls/sys_enter_recvmsg.
	recvLink, err := link.Tracepoint("syscalls", "sys_enter_recvmsg",
		l.objs.TracepointSysEnterRecvmsg, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching sys_enter_recvmsg: %w", err)
	}
	l.links = append(l.links, recvLink)

	// Open ring buffer reader.
	reader, err := ringbuf.NewReader(l.objs.DnsEvents)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("opening dns ring buffer: %w", err)
	}
	l.reader = reader

	l.logger.Info("dns_monitor eBPF program loaded and attached")
	return closerFunc(l.close), nil
}

// Events implements Loader.
func (l *DNSMonitorLoader) Events(ctx context.Context) (<-chan RawEvent, error) {
	if l.reader == nil {
		return nil, fmt.Errorf("loader not loaded; call Load() first")
	}
	ch := make(chan RawEvent, 256)
	go l.readLoop(ctx, ch)
	return ch, nil
}

func (l *DNSMonitorLoader) readLoop(ctx context.Context, ch chan<- RawEvent) {
	defer close(ch)
	for {
		record, err := l.reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			l.logger.Warn("dns ring buffer read error", "error", err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case ch <- RawEvent{
			Type: EventDNSMonitor,
			Data: bytes.Clone(record.RawSample),
		}:
		}
	}
}

func (l *DNSMonitorLoader) close() {
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

// DecodeDNSEvent decodes a raw event into a typed DNSEvent.
func DecodeDNSEvent(data []byte) (*DNSEvent, error) {
	var event DNSEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding dns event: %w", err)
	}
	return &event, nil
}
