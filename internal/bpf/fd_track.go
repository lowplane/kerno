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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I c/headers" -target bpfel -type fd_event fdTrack c/fd_track.c

// FDTrackLoader manages the fd_track eBPF program.
type FDTrackLoader struct {
	logger *slog.Logger
	objs   *fdTrackObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// NewFDTrackLoader creates a new loader.
func NewFDTrackLoader(logger *slog.Logger) *FDTrackLoader {
	return &FDTrackLoader{
		logger: logger.With("loader", "fd_track"),
	}
}

// Name implements Loader.
func (l *FDTrackLoader) Name() string {
	return "fd_track"
}

// Load implements Loader.
func (l *FDTrackLoader) Load() (io.Closer, error) {
	l.objs = &fdTrackObjects{}
	if err := loadFdTrackObjects(l.objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	// Attach tracepoint/syscalls/sys_exit_openat.
	openLink, err := link.Tracepoint("syscalls", "sys_exit_openat", l.objs.TracepointSysExitOpenat, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching sys_exit_openat tracepoint: %w", err)
	}
	l.links = append(l.links, openLink)

	// Attach tracepoint/syscalls/sys_exit_close.
	closeLink, err := link.Tracepoint("syscalls", "sys_exit_close", l.objs.TracepointSysExitClose, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching sys_exit_close tracepoint: %w", err)
	}
	l.links = append(l.links, closeLink)

	// Open ring buffer reader.
	reader, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	l.reader = reader

	l.logger.Info("fd_track eBPF program loaded and attached")

	return closerFunc(l.close), nil
}

// Events implements Loader.
func (l *FDTrackLoader) Events(ctx context.Context) (<-chan RawEvent, error) {
	if l.reader == nil {
		return nil, fmt.Errorf("loader not loaded; call Load() first")
	}

	ch := make(chan RawEvent, 256)
	go l.readLoop(ctx, ch)
	return ch, nil
}

func (l *FDTrackLoader) readLoop(ctx context.Context, ch chan<- RawEvent) {
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
			Type: EventFDTrack,
			Data: bytes.Clone(record.RawSample),
		}:
		}
	}
}

func (l *FDTrackLoader) close() {
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

// DecodeFDEvent decodes a raw event into a typed FDEvent.
func DecodeFDEvent(data []byte) (*FDEvent, error) {
	var event FDEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding fd event: %w", err)
	}
	return &event, nil
}
