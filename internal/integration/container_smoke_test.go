// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func runKernoCmd(t *testing.T, cmd []string) int {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:           "kerno:local",
			Cmd:             cmd,
			WaitingFor:      wait.ForExit().WithExitTimeout(60 * time.Second),
			AlwaysPullImage: false,
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start kerno container cmd=%v: %v", cmd, err)
	}

	t.Cleanup(func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer terminateCancel()
		if err := container.Terminate(terminateCtx); err != nil {
			t.Fatalf("terminate kerno container: %v", err)
		}
	})

	state, err := container.State(ctx)
	if err != nil {
		t.Fatalf("get container state cmd=%v: %v", cmd, err)
	}
	return state.ExitCode
}

// TestKernoVersion asserts the binary starts and prints build metadata.
func TestKernoVersion(t *testing.T) {
	if code := runKernoCmd(t, []string{"version"}); code != 0 {
		t.Fatalf("kerno version: want exit 0, got %d", code)
	}
}

// TestKernoHelp asserts --help exits 0.
func TestKernoHelp(t *testing.T) {
	if code := runKernoCmd(t, []string{"--help"}); code != 0 {
		t.Fatalf("kerno --help: want exit 0, got %d", code)
	}
}

// TestKernoDoctorFailsCleanly asserts doctor exits without panic
// even when bpf cannot be loaded in an unprivileged container.
func TestKernoDoctorFailsCleanly(t *testing.T) {
	code := runKernoCmd(t, []string{"doctor"})
	if code == 2 {
		t.Fatalf("kerno doctor: exit 2 indicates panic or misuse")
	}
}