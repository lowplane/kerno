// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

func newAuditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "audit",
		Short: "Audit security-sensitive kernel events",
		Long:  "The audit command uses Linux inotify and is only supported on Linux.",
		RunE: func(*cobra.Command, []string) error {
			return errors.New("audit command is only supported on Linux")
		},
	}
}
