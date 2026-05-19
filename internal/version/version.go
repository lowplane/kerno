// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"fmt"
	"runtime"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"built"`
	GoVersion string `json:"go"`
	OS        string `json:"-"`
	Arch      string `json:"-"`
	Platform  string `json:"platform"`
}

func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

func (i Info) String() string {
	return fmt.Sprintf(
		"kerno version %s\n  commit:    %s\n  built:     %s\n  go:        %s\n  platform:  %s/%s",
		i.Version,
		i.Commit,
		i.Date,
		i.GoVersion,
		i.OS,
		i.Arch,
	)
}

func (i Info) Short() string {
	return i.Version
}
