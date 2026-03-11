// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

// Package bpf provides the eBPF program loaders and Go event types.
//
// Each eBPF program has:
//   - A .c source file compiled by clang to BPF bytecode
//   - A Go loader file with a //go:generate bpf2go directive
//   - Typed Go event structs matching the C structs in kerno.h
//
// The Loader interface abstracts eBPF program lifecycle management.
package bpf

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

// Loader is the interface that all eBPF program loaders must implement.
// Each loader manages the lifecycle of one eBPF program: loading it into
// the kernel, attaching to hook points, and reading events from ring buffers.
type Loader interface {
	// Name returns a human-readable identifier for this loader (e.g., "syscall_latency").
	Name() string

	// Load loads the eBPF program into the kernel and attaches to hook points.
	// The returned io.Closer detaches and unloads the program when closed.
	Load() (io.Closer, error)

	// Events returns a channel that emits raw events from the eBPF ring buffer.
	// The channel is closed when the context is canceled or the loader is closed.
	Events(ctx context.Context) (<-chan RawEvent, error)
}

// RawEvent is an untyped event read from the ring buffer.
// The Type field identifies which event struct to decode into.
type RawEvent struct {
	// Type is the event discriminator (EVENT_SYSCALL_LATENCY, etc.).
	Type EventType

	// Data is the raw bytes of the event struct.
	Data []byte
}

// EventType discriminates the union of event types.
type EventType uint8

const (
	EventSyscallLatency EventType = 1
	EventTCPMonitor     EventType = 2
	EventOOMKill        EventType = 3
	EventDiskIO         EventType = 4
	EventSchedDelay     EventType = 5
	EventFDTrack        EventType = 6
	EventFileAudit      EventType = 7
)

// String returns the human-readable name of the event type.
func (t EventType) String() string {
	switch t {
	case EventSyscallLatency:
		return "syscall_latency"
	case EventTCPMonitor:
		return "tcp_monitor"
	case EventOOMKill:
		return "oom_kill"
	case EventDiskIO:
		return "disk_io"
	case EventSchedDelay:
		return "sched_delay"
	case EventFDTrack:
		return "fd_track"
	case EventFileAudit:
		return "file_audit"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// LoaderSet manages the lifecycle of multiple eBPF program loaders.
type LoaderSet struct {
	loaders []Loader
	closers []io.Closer
	logger  *slog.Logger
}

// NewLoaderSet creates a new set of eBPF program loaders.
func NewLoaderSet(logger *slog.Logger, loaders ...Loader) *LoaderSet {
	return &LoaderSet{
		loaders: loaders,
		logger:  logger,
	}
}

// LoadAll loads all eBPF programs into the kernel.
// Returns an error if any program fails to load, after cleaning up
// all previously loaded programs.
func (s *LoaderSet) LoadAll() error {
	for _, l := range s.loaders {
		s.logger.Info("loading eBPF program", "name", l.Name())

		closer, err := l.Load()
		if err != nil {
			// Clean up everything loaded so far.
			s.Close()
			return fmt.Errorf("loading %s: %w", l.Name(), err)
		}
		s.closers = append(s.closers, closer)

		s.logger.Info("loaded eBPF program", "name", l.Name())
	}
	return nil
}

// Close detaches and unloads all eBPF programs.
func (s *LoaderSet) Close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		if err := s.closers[i].Close(); err != nil {
			s.logger.Warn("error closing eBPF program", "error", err)
		}
	}
	s.closers = nil
}

// Loaders returns the underlying loaders for event consumption.
func (s *LoaderSet) Loaders() []Loader {
	return s.loaders
}

// closerFunc adapts a plain function to the io.Closer interface.
type closerFunc func()

func (f closerFunc) Close() error {
	f()
	return nil
}
