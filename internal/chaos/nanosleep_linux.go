// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package chaos

import "golang.org/x/sys/unix"

func chaosNanosleep(nsec int64) error {
	ts := unix.Timespec{Sec: 0, Nsec: nsec}
	return unix.Nanosleep(&ts, nil)
}
