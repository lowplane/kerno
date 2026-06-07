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

func TestDockerBackedHarnessStartsPinnedContainer(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:           "docker.io/library/alpine:3.20",
			Cmd:             []string{"sh", "-c", "echo kerno-integration-ready && sleep 30"},
			WaitingFor:      wait.ForLog("kerno-integration-ready").WithStartupTimeout(30 * time.Second),
			AlwaysPullImage: false,
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start integration smoke container: %v", err)
	}

	t.Cleanup(func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer terminateCancel()

		if err := container.Terminate(terminateCtx); err != nil {
			t.Fatalf("terminate integration smoke container: %v", err)
		}
	})

	state, err := container.State(ctx)
	if err != nil {
		t.Fatalf("read smoke container state: %v", err)
	}
	if !state.Running {
		t.Fatalf("expected smoke container to be running, got state %+v", state)
	}
}
