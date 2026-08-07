// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountProcFDs(t *testing.T) {
	// Override procDir
	oldProcDir := procDir
	tmpDir, err := os.MkdirTemp("", "kerno-proc-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	procDir = tmpDir
	defer func() { procDir = oldProcDir }()

	var pid uint32 = 1234
	fdPath := filepath.Join(tmpDir, "1234", "fd")

	// Test case 1: Directory doesn't exist (unknown/process exited)
	count, err := CountProcFDs(pid)
	if err == nil {
		t.Errorf("expected error for non-existent fd directory, got nil")
	}
	if count != 0 {
		t.Errorf("expected count to be 0 on error, got %d", count)
	}

	// Create the fd directory
	if err := os.MkdirAll(fdPath, 0755); err != nil {
		t.Fatalf("failed to create mock fd dir: %v", err)
	}

	// Test case 2: Empty directory
	count, err = CountProcFDs(pid)
	if err != nil {
		t.Errorf("unexpected error for empty fd directory: %v", err)
	}
	if count != 0 {
		t.Errorf("expected count to be 0 for empty directory, got %d", count)
	}

	// Create mock fd files
	files := []string{"0", "1", "2", "3", "4"}
	for _, fname := range files {
		if err := os.WriteFile(filepath.Join(fdPath, fname), []byte(""), 0644); err != nil {
			t.Fatalf("failed to write mock fd file %s: %v", fname, err)
		}
	}

	// Test case 3: 5 open FDs
	count, err = CountProcFDs(pid)
	if err != nil {
		t.Errorf("unexpected error counting fds: %v", err)
	}
	if count != len(files) {
		t.Errorf("expected count to be %d, got %d", len(files), count)
	}
}

func TestReadProcFDLimit(t *testing.T) {
	// Override procDir
	oldProcDir := procDir
	tmpDir, err := os.MkdirTemp("", "kerno-proc-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	procDir = tmpDir
	defer func() { procDir = oldProcDir }()

	var pid uint32 = 1234
	limitsDir := filepath.Join(tmpDir, "1234")
	if err := os.MkdirAll(limitsDir, 0755); err != nil {
		t.Fatalf("failed to create limits dir: %v", err)
	}
	limitsPath := filepath.Join(limitsDir, "limits")

	// Test case 1: Missing limits file
	lim, err := ReadProcFDLimit(pid)
	if err == nil {
		t.Errorf("expected error for missing limits file, got nil")
	}
	if lim != 0 {
		t.Errorf("expected limit to be 0 on error, got %d", lim)
	}

	// Test case 2: Valid limits file
	mockLimits := `Limit                     Soft Limit           Hard Limit           Units     
Max cpu time              unlimited            unlimited            seconds   
Max open files            65536                65536                files     
Max locked memory         8388608              8388608              bytes     
`
	if err := os.WriteFile(limitsPath, []byte(mockLimits), 0644); err != nil {
		t.Fatalf("failed to write mock limits: %v", err)
	}

	lim, err = ReadProcFDLimit(pid)
	if err != nil {
		t.Errorf("unexpected error reading limits: %v", err)
	}
	if lim != 65536 {
		t.Errorf("expected limit to be 65536, got %d", lim)
	}

	// Test case 3: Limits file with "unlimited"
	mockLimitsUnlimited := `Limit                     Soft Limit           Hard Limit           Units     
Max cpu time              unlimited            unlimited            seconds   
Max open files            unlimited            unlimited            files     
`
	if err := os.WriteFile(limitsPath, []byte(mockLimitsUnlimited), 0644); err != nil {
		t.Fatalf("failed to write mock limits: %v", err)
	}

	lim, err = ReadProcFDLimit(pid)
	if err != nil {
		t.Errorf("unexpected error reading limits: %v", err)
	}
	if lim != 0 {
		t.Errorf("expected limit to be 0 (unknown) for unlimited, got %d", lim)
	}

	// Test case 4: Limits file with no Max open files line
	mockLimitsMissingLine := `Limit                     Soft Limit           Hard Limit           Units     
Max cpu time              unlimited            unlimited            seconds   
`
	if err := os.WriteFile(limitsPath, []byte(mockLimitsMissingLine), 0644); err != nil {
		t.Fatalf("failed to write mock limits: %v", err)
	}

	lim, err = ReadProcFDLimit(pid)
	if err == nil {
		t.Errorf("expected error when Max open files is missing, got nil")
	}
	if lim != 0 {
		t.Errorf("expected limit to be 0, got %d", lim)
	}
}
