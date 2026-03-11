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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I c/headers" -target bpfel -type syscall_event syscallLatency c/syscall_latency.c

// SyscallLatencyLoader manages the syscall_latency eBPF program.
type SyscallLatencyLoader struct {
	logger *slog.Logger
	objs   *syscallLatencyObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// NewSyscallLatencyLoader creates a new loader.
func NewSyscallLatencyLoader(logger *slog.Logger) *SyscallLatencyLoader {
	return &SyscallLatencyLoader{
		logger: logger.With("loader", "syscall_latency"),
	}
}

// Name implements Loader.
func (l *SyscallLatencyLoader) Name() string {
	return "syscall_latency"
}

// Load implements Loader.
func (l *SyscallLatencyLoader) Load() (io.Closer, error) {
	l.objs = &syscallLatencyObjects{}
	if err := loadSyscallLatencyObjects(l.objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	// Attach tracepoint/raw_syscalls/sys_enter.
	enterLink, err := link.Tracepoint("raw_syscalls", "sys_enter", l.objs.TracepointSysEnter, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching sys_enter tracepoint: %w", err)
	}
	l.links = append(l.links, enterLink)

	// Attach tracepoint/raw_syscalls/sys_exit.
	exitLink, err := link.Tracepoint("raw_syscalls", "sys_exit", l.objs.TracepointSysExit, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching sys_exit tracepoint: %w", err)
	}
	l.links = append(l.links, exitLink)

	// Open ring buffer reader.
	reader, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	l.reader = reader

	l.logger.Info("syscall_latency eBPF program loaded and attached")

	return closerFunc(l.close), nil
}

// Events implements Loader.
func (l *SyscallLatencyLoader) Events(ctx context.Context) (<-chan RawEvent, error) {
	if l.reader == nil {
		return nil, fmt.Errorf("loader not loaded; call Load() first")
	}

	ch := make(chan RawEvent, 256)
	go l.readLoop(ctx, ch)
	return ch, nil
}

func (l *SyscallLatencyLoader) readLoop(ctx context.Context, ch chan<- RawEvent) {
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
			Type: EventSyscallLatency,
			Data: bytes.Clone(record.RawSample),
		}:
		}
	}
}

func (l *SyscallLatencyLoader) close() {
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

// DecodeSyscallEvent decodes a raw event into a typed SyscallEvent.
func DecodeSyscallEvent(data []byte) (*SyscallEvent, error) {
	var event SyscallEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding syscall event: %w", err)
	}
	return &event, nil
}
