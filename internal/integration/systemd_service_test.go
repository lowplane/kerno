// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

const systemdRuntimeImage = "docker.io/jrei/systemd-ubuntu@sha256:c746f3cb801d8c070ec230a0eb3414d9b537f5d4b646a27a776cde3870d6f951"

func TestSystemdUnitStartsAndServesHealthz(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	repoRoot := integrationRepoRoot(t)
	binPath := buildKernoBinary(t, ctx, repoRoot)
	unitPath := filepath.Join(repoRoot, "deploy/systemd/kerno.service")
	configPath := filepath.Join(repoRoot, "deploy/systemd/kerno.yaml")

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: systemdRuntimeImage,
			WaitingFor: wait.ForExec([]string{
				"bash", "-lc", "ps -p 1 -o comm= | grep -qx systemd",
			}).WithStartupTimeout(45 * time.Second),
			HostConfigModifier: func(hc *dockercontainer.HostConfig) {
				hc.Privileged = true
				hc.CgroupnsMode = "host"
				hc.Binds = append(hc.Binds, "/sys/fs/cgroup:/sys/fs/cgroup:rw")
			},
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("skip systemd service integration test: start systemd container: %v", err)
	}

	t.Cleanup(func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer terminateCancel()
		_ = container.Terminate(terminateCtx)
	})

	t.Cleanup(func() {
		if !t.Failed() {
			return
		}

		status, _, _ := execInContainer(ctx, container, []string{"systemctl", "status", "kerno", "--no-pager", "-l"})
		journal, _, _ := execInContainer(ctx, container, []string{"journalctl", "-u", "kerno", "--no-pager", "-n", "200"})
		t.Logf("systemctl status kerno:\n%s", status)
		t.Logf("journalctl -u kerno:\n%s", journal)
	})

	mustExecInContainer(t, ctx, container, []string{"mkdir", "-p", "/etc/kerno"})

	if err := container.CopyFileToContainer(ctx, binPath, "/usr/bin/kerno", 0o755); err != nil {
		t.Fatalf("copy kerno binary into systemd container: %v", err)
	}
	if err := container.CopyFileToContainer(ctx, unitPath, "/etc/systemd/system/kerno.service", 0o644); err != nil {
		t.Fatalf("copy systemd unit into systemd container: %v", err)
	}
	if err := container.CopyFileToContainer(ctx, configPath, "/etc/kerno/config.yaml", 0o644); err != nil {
		t.Fatalf("copy systemd config into systemd container: %v", err)
	}

	mustExecInContainer(t, ctx, container, []string{"systemctl", "daemon-reload"})
	mustExecInContainer(t, ctx, container, []string{"systemctl", "start", "kerno"})

	waitForSystemdState(t, ctx, container, "kerno", "active")

	body := waitForContainerHealthz(t, ctx, container, "http://127.0.0.1:9090/healthz")
	if got := body["status"]; got != "ok" {
		t.Fatalf("healthz status = %v, want ok (body=%v)", got, body)
	}
	if _, ok := body["programs_loaded"].(float64); !ok {
		t.Fatalf("healthz missing numeric programs_loaded (body=%v)", body)
	}
	if _, ok := body["programs_total"].(float64); !ok {
		t.Fatalf("healthz missing numeric programs_total (body=%v)", body)
	}

	mustExecInContainer(t, ctx, container, []string{"systemctl", "stop", "kerno"})
	waitForSystemdState(t, ctx, container, "kerno", "inactive")
}

func execInContainer(ctx context.Context, container testcontainers.Container, cmd []string) (string, int, error) {
	exitCode, reader, err := container.Exec(ctx, cmd, tcexec.Multiplexed())
	if err != nil {
		return "", exitCode, err
	}

	output, readErr := io.ReadAll(reader)
	if readErr != nil {
		return "", exitCode, readErr
	}

	return string(output), exitCode, nil
}

func mustExecInContainer(t *testing.T, ctx context.Context, container testcontainers.Container, cmd []string) string {
	t.Helper()

	output, exitCode, err := execInContainer(ctx, container, cmd)
	if err != nil {
		t.Fatalf("exec %q in container: %v", strings.Join(cmd, " "), err)
	}
	if exitCode != 0 {
		t.Fatalf("exec %q in container exited %d\noutput:\n%s", strings.Join(cmd, " "), exitCode, output)
	}

	return output
}

func waitForSystemdState(t *testing.T, ctx context.Context, container testcontainers.Container, unit string, want string) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	cmd := []string{"systemctl", "is-active", unit}

	for time.Now().Before(deadline) {
		output, _, err := execInContainer(ctx, container, cmd)
		if err == nil && strings.TrimSpace(output) == want {
			return
		}

		time.Sleep(250 * time.Millisecond)
	}

	output, _, _ := execInContainer(ctx, container, cmd)
	t.Fatalf("timed out waiting for %s to become %s (last output=%q)", unit, want, strings.TrimSpace(output))
}

func waitForContainerHealthz(t *testing.T, ctx context.Context, container testcontainers.Container, url string) map[string]any {
	t.Helper()

	python := fmt.Sprintf(
		`import json, urllib.request; print(json.dumps(json.load(urllib.request.urlopen(%q))))`,
		url,
	)

	deadline := time.Now().Add(20 * time.Second)
	cmd := []string{"python3", "-c", python}

	for time.Now().Before(deadline) {
		output, exitCode, err := execInContainer(ctx, container, cmd)
		if err == nil && exitCode == 0 {
			var body map[string]any
			if jsonErr := json.Unmarshal([]byte(output), &body); jsonErr == nil {
				return body
			}
		}

		time.Sleep(250 * time.Millisecond)
	}

	output, _, _ := execInContainer(ctx, container, cmd)
	t.Fatalf("timed out waiting for %s (last output=%q)", url, output)
	return nil
}
