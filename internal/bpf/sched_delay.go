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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I c/headers" -target bpfel -type sched_event schedDelay c/sched_delay.c

// SchedDelayLoader manages the sched_delay eBPF program.
type SchedDelayLoader struct {
	logger *slog.Logger
	objs   *schedDelayObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// NewSchedDelayLoader creates a new loader.
func NewSchedDelayLoader(logger *slog.Logger) *SchedDelayLoader {
	return &SchedDelayLoader{
		logger: logger.With("loader", "sched_delay"),
	}
}

// Name implements Loader.
func (l *SchedDelayLoader) Name() string {
	return "sched_delay"
}

// Load implements Loader.
func (l *SchedDelayLoader) Load() (io.Closer, error) {
	l.objs = &schedDelayObjects{}
	if err := loadSchedDelayObjects(l.objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	// Attach tracepoint/sched/sched_wakeup.
	wakeupLink, err := link.Tracepoint("sched", "sched_wakeup", l.objs.TracepointSchedWakeup, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching sched_wakeup tracepoint: %w", err)
	}
	l.links = append(l.links, wakeupLink)

	// Attach tracepoint/sched/sched_switch.
	switchLink, err := link.Tracepoint("sched", "sched_switch", l.objs.TracepointSchedSwitch, nil)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("attaching sched_switch tracepoint: %w", err)
	}
	l.links = append(l.links, switchLink)

	// Open ring buffer reader.
	reader, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	l.reader = reader

	l.logger.Info("sched_delay eBPF program loaded and attached")

	return closerFunc(l.close), nil
}

// Events implements Loader.
func (l *SchedDelayLoader) Events(ctx context.Context) (<-chan RawEvent, error) {
	if l.reader == nil {
		return nil, fmt.Errorf("loader not loaded; call Load() first")
	}

	ch := make(chan RawEvent, 256)
	go l.readLoop(ctx, ch)
	return ch, nil
}

func (l *SchedDelayLoader) readLoop(ctx context.Context, ch chan<- RawEvent) {
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
			Type: EventSchedDelay,
			Data: bytes.Clone(record.RawSample),
		}:
		}
	}
}

func (l *SchedDelayLoader) close() {
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

// DecodeSchedEvent decodes a raw event into a typed SchedEvent.
func DecodeSchedEvent(data []byte) (*SchedEvent, error) {
	var event SchedEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding sched event: %w", err)
	}
	return &event, nil
}
