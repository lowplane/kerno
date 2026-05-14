// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import "unsafe"

// unsafePointer is a tiny adapter that hides the unsafe import from
// audit.go so the rest of the file stays linter-friendly. The cast is
// only used to overlay struct inotify_event onto a kernel-emitted
// byte buffer — same pattern the syscall package itself uses.
//
//nolint:gosec // intentional: required to decode inotify_event blobs
func unsafePointer[T any](b *T) unsafe.Pointer {
	return unsafe.Pointer(b)
}
