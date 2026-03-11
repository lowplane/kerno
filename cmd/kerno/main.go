// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

// Kerno is an eBPF-based kernel observability engine for Linux.
//
// Usage:
//
//	sudo kerno doctor           # 30-second kernel diagnostic
//	sudo kerno start            # daemon mode with Prometheus
//	kerno version               # print version info
//
// See https://github.com/lowplane/kerno for documentation.
package main

import (
	"fmt"
	"os"

	"github.com/lowplane/kerno/internal/cli"
)

func main() {
	if err := cli.New().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
