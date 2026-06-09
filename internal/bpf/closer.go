//go:build ebpf

// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

// closerFunc adapts a plain function to the io.Closer interface.
type closerFunc func()

func (f closerFunc) Close() error {
	f()
	return nil
}
