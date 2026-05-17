// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package main generates man pages for kerno CLI commands.
package main

import (
	"log"
	"os"

	"github.com/spf13/cobra/doc"

	"github.com/optiqor/kerno/internal/cli"
)

func main() {
	root := cli.New()
	manDir := "docs/man"

	if err := os.MkdirAll(manDir, 0o750); err != nil {
		log.Fatalf("creating man dir: %v", err)
	}

	header := &doc.GenManHeader{
		Title:   "KERNO",
		Section: "1",
	}

	if err := doc.GenManTree(root, header, manDir); err != nil {
		log.Fatalf("generating man pages: %v", err)
	}

	log.Printf("Generated man pages in %s", manDir)
}
