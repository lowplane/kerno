// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package main generates man pages for kerno CLI commands.
package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"

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

	entries, err := os.ReadDir(manDir)
	if err != nil {
		log.Fatalf("reading man dir: %v", err)
	}

	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".1" {
			continue
		}
		oldPath := filepath.Join(manDir, e.Name())
		newName := renameManFile(e.Name())
		if newName != e.Name() {
			newPath := filepath.Join(manDir, newName)
			if err := os.Rename(oldPath, newPath); err != nil {
				log.Printf("warning: failed to rename %s: %v", e.Name(), err)
			}
		}
	}

	log.Printf("Generated man pages in %s", manDir)
}

func renameManFile(name string) string {
	base := strings.TrimSuffix(name, ".1")
	var result strings.Builder
	for i, r := range base {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteByte('-')
		}
		result.WriteRune(r)
	}
	return result.String() + ".1"
}
