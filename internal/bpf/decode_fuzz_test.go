// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

import "testing"

// The decode functions take untrusted bytes from the kernel ringbuf and
// reconstruct typed events. Any panic on malformed input is a real
// production risk — a corrupted ringbuf record would crash the daemon.
//
// These fuzz tests run binary.Read against random/short/oversized
// inputs and assert every Decode* function returns a (possibly-error)
// result without panicking.
//
// Run a focused fuzz with:
//
//	go test -fuzz=FuzzDecodeSyscallEvent ./internal/bpf -fuzztime=10s

func FuzzDecodeSyscallEvent(f *testing.F) {
	// Seed corpus: a zero-length, a tiny, and an oversize input.
	f.Add([]byte{})
	f.Add(make([]byte, 4))
	f.Add(make([]byte, 1024))
	// One properly-sized buffer.
	f.Add(make([]byte, 48))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeSyscallEvent(data) // must not panic
	})
}

func FuzzDecodeTCPEvent(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 1024))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeTCPEvent(data)
	})
}

func FuzzDecodeOOMEvent(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeOOMEvent(data)
	})
}

func FuzzDecodeDiskEvent(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeDiskEvent(data)
	})
}

func FuzzDecodeSchedEvent(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeSchedEvent(data)
	})
}

func FuzzDecodeFDEvent(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeFDEvent(data)
	})
}
