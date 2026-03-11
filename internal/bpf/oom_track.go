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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I c/headers" -target bpfel -type oom_event oomTrack c/oom_track.c

// OOMTrackLoader manages the oom_track eBPF program.
type OOMTrackLoader struct {
	logger *slog.Logger
	objs   *oomTrackObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// NewOOMTrackLoader creates a new loader.
func NewOOMTrackLoader(logger *slog.Logger) *OOMTrackLoader {
	return &OOMTrackLoader{
		logger: logger.With("loader", "oom_track"),
	}
}

// Name implements Loader.
func (l *OOMTrackLoader) Name() string {
	return "oom_track"
}

// Load implements Loader.
func (l *OOMTrackLoader) Load() (io.Closer, error) {
	l.objs = &oomTrackObjects{}
	if err := loadOomTrackObjects(l.objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	// Attach kprobe/oom_kill_process.
	kp, err := link.Kprobe("oom_kill_process", l.objs.KprobeOomKill, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching kprobe oom_kill_process: %w", err)
	}
	l.links = append(l.links, kp)

	// Open ring buffer reader.
	reader, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	l.reader = reader

	l.logger.Info("oom_track eBPF program loaded and attached")

	return closerFunc(l.close), nil
}

// Events implements Loader.
func (l *OOMTrackLoader) Events(ctx context.Context) (<-chan RawEvent, error) {
	if l.reader == nil {
		return nil, fmt.Errorf("loader not loaded; call Load() first")
	}

	ch := make(chan RawEvent, 64)
	go l.readLoop(ctx, ch)
	return ch, nil
}

func (l *OOMTrackLoader) readLoop(ctx context.Context, ch chan<- RawEvent) {
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
			Type: EventOOMKill,
			Data: bytes.Clone(record.RawSample),
		}:
		}
	}
}

func (l *OOMTrackLoader) close() {
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

// DecodeOOMEvent decodes a raw event into a typed OOMEvent.
func DecodeOOMEvent(data []byte) (*OOMEvent, error) {
	var event OOMEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding oom event: %w", err)
	}
	return &event, nil
}
