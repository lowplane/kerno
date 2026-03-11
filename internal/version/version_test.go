// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	info := Get()

	if info.GoVersion == "" {
		t.Error("GoVersion should not be empty")
	}
	if !strings.HasPrefix(info.GoVersion, "go") {
		t.Errorf("GoVersion should start with 'go', got %q", info.GoVersion)
	}
	if info.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", info.OS, runtime.GOOS)
	}
	if info.Arch != runtime.GOARCH {
		t.Errorf("Arch = %q, want %q", info.Arch, runtime.GOARCH)
	}
}

func TestInfoString(t *testing.T) {
	info := Info{
		Version:   "v0.1.0",
		Commit:    "abc1234",
		Date:      "2026-01-01T00:00:00Z",
		GoVersion: "go1.22.0",
		OS:        "linux",
		Arch:      "amd64",
	}

	s := info.String()
	for _, want := range []string{"v0.1.0", "abc1234", "2026-01-01T00:00:00Z", "go1.22.0", "linux/amd64"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, want to contain %q", s, want)
		}
	}
}

func TestInfoShort(t *testing.T) {
	info := Info{Version: "v1.2.3"}
	if got := info.Short(); got != "kerno v1.2.3" {
		t.Errorf("Short() = %q, want %q", got, "kerno v1.2.3")
	}
}
