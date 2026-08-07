// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var procDir = "/proc"

// CountProcFDs counts open file descriptors for pid by listing /proc/<pid>/fd.
// Returns (count, nil) on success; (0, err) if the directory is unreadable
// (process exited, permission denied, etc.). Callers should treat 0 as
// "unknown" rather than "zero open fds".
func CountProcFDs(pid uint32) (int, error) {
	dir := fmt.Sprintf("%s/%d/fd", procDir, pid)
	f, err := os.Open(dir) //nolint:gosec // dir is constructed from the controlled procDir
	if err != nil {
		return 0, err
	}
	defer f.Close()
	// Readdirnames is cheaper than Readdir — no stat per entry.
	names, err := f.Readdirnames(-1)
	if err != nil {
		return 0, err
	}
	return len(names), nil
}

// ReadProcFDLimit reads the soft RLIMIT_NOFILE for pid from
// /proc/<pid>/limits. Returns (limit, nil) on success; (0, err) on failure.
func ReadProcFDLimit(pid uint32) (int, error) {
	path := fmt.Sprintf("%s/%d/limits", procDir, pid)
	f, err := os.Open(path) //nolint:gosec // path is constructed from the controlled procDir
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Max open files") {
			continue
		}
		// Format: "Max open files            65536                65536                files"
		fields := strings.Fields(line)
		// fields[3] is the soft limit; "unlimited" maps to 0 (treat as unknown).
		if len(fields) < 4 || fields[3] == "unlimited" {
			return 0, nil
		}
		return strconv.Atoi(fields[3])
	}
	return 0, fmt.Errorf("RLIMIT_NOFILE not found in %s", path)
}
