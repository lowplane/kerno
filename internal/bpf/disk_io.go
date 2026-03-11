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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I c/headers" -target bpfel -type disk_event diskIO c/disk_io.c

// DiskIOLoader manages the disk_io eBPF program.
type DiskIOLoader struct {
	logger *slog.Logger
	objs   *diskIOObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// NewDiskIOLoader creates a new loader.
func NewDiskIOLoader(logger *slog.Logger) *DiskIOLoader {
	return &DiskIOLoader{
		logger: logger.With("loader", "disk_io"),
	}
}

// Name implements Loader.
func (l *DiskIOLoader) Name() string {
	return "disk_io"
}

// Load implements Loader.
func (l *DiskIOLoader) Load() (io.Closer, error) {
	l.objs = &diskIOObjects{}
	if err := loadDiskIOObjects(l.objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	// Attach tracepoint/block/block_rq_issue.
	issueLink, err := link.Tracepoint("block", "block_rq_issue", l.objs.TracepointBlockRqIssue, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching block_rq_issue tracepoint: %w", err)
	}
	l.links = append(l.links, issueLink)

	// Attach tracepoint/block/block_rq_complete.
	completeLink, err := link.Tracepoint("block", "block_rq_complete", l.objs.TracepointBlockRqComplete, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching block_rq_complete tracepoint: %w", err)
	}
	l.links = append(l.links, completeLink)

	// Open ring buffer reader.
	reader, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	l.reader = reader

	l.logger.Info("disk_io eBPF program loaded and attached")

	return closerFunc(l.close), nil
}

// Events implements Loader.
func (l *DiskIOLoader) Events(ctx context.Context) (<-chan RawEvent, error) {
	if l.reader == nil {
		return nil, fmt.Errorf("loader not loaded; call Load() first")
	}

	ch := make(chan RawEvent, 256)
	go l.readLoop(ctx, ch)
	return ch, nil
}

func (l *DiskIOLoader) readLoop(ctx context.Context, ch chan<- RawEvent) {
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
			Type: EventDiskIO,
			Data: bytes.Clone(record.RawSample),
		}:
		}
	}
}

func (l *DiskIOLoader) close() {
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

// DecodeDiskEvent decodes a raw event into a typed DiskEvent.
func DecodeDiskEvent(data []byte) (*DiskEvent, error) {
	var event DiskEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding disk event: %w", err)
	}
	return &event, nil
}
