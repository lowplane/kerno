// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

// Package version exposes the build metadata injected at compile time via ldflags.
// These values are set by the Makefile using:
//
//	-ldflags "-X github.com/lowplane/kerno/internal/version.Version=v0.1.0 ..."
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Build-time values injected via -ldflags.
var (
	// Version is the semantic version (e.g., "v0.1.0"). Set at build time.
	Version = "dev"

	// Commit is the short git commit hash. Set at build time.
	Commit = "unknown"

	// Date is the build date in ISO 8601 format. Set at build time.
	Date = "unknown"
)

// Info holds structured build metadata.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the current build information.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String returns a human-readable version string.
func (i Info) String() string {
	return fmt.Sprintf("kerno %s (commit: %s, built: %s, %s, %s/%s)",
		i.Version, i.Commit, i.Date, i.GoVersion, i.OS, i.Arch)
}

// Short returns just "kerno <version>".
func (i Info) Short() string {
	return fmt.Sprintf("kerno %s", i.Version)
}

func init() {
	// If binaries were installed via `go install` without ldflags,
	// attempt to extract version from Go module info.
	if Version != "dev" {
		return
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		Version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 8 {
				Commit = s.Value[:8]
			} else {
				Commit = s.Value
			}
		case "vcs.time":
			Date = s.Value
		}
	}
}
