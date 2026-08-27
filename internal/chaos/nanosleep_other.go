// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package chaos

import "time"

func chaosNanosleep(nsec int64) error {
	time.Sleep(time.Duration(nsec))
	return nil
}
