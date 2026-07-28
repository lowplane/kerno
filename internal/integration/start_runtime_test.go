// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestStartCommandServesHealthAndStopsCleanly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skip start runtime integration test: requires root")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	repoRoot := integrationRepoRoot(t)
	binPath := buildKernoBinary(t, ctx, repoRoot)
	configPath := writeRuntimeConfig(t)
	addr := reserveLoopbackAddr(t)
	healthURL := "http://" + addr + "/healthz"

	cmd := exec.CommandContext(
		ctx,
		binPath,
		"--config", configPath,
		"--log-format", "json",
		"start",
		"--prometheus-addr", addr,
	)
	cmd.Dir = repoRoot

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start kerno runtime command: %v", err)
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	t.Cleanup(func() {
		if cmd.Process == nil {
			return
		}

		select {
		case <-waitCh:
			return
		default:
		}

		_ = cmd.Process.Signal(syscall.SIGKILL)
		select {
		case <-waitCh:
		case <-time.After(5 * time.Second):
		}
	})

	body := waitForHealthz(t, ctx, healthURL, waitCh, &stdout, &stderr)
	if got := body["status"]; got != "ok" {
		t.Fatalf("healthz status = %v, want ok (body=%v)", got, body)
	}
	if _, ok := body["programs_loaded"].(float64); !ok {
		t.Fatalf("healthz missing numeric programs_loaded (body=%v)", body)
	}
	if _, ok := body["programs_total"].(float64); !ok {
		t.Fatalf("healthz missing numeric programs_total (body=%v)", body)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to kerno runtime command: %v", err)
	}

	select {
	case err := <-waitCh:
		if err != nil {
			t.Fatalf("kerno runtime command exited with error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for kerno runtime command to stop\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	}
}

func integrationRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod in any parent directory")
		}
		dir = parent
	}
}

func buildKernoBinary(t *testing.T, ctx context.Context, repoRoot string) string {
	t.Helper()

	binPath := filepath.Join(t.TempDir(), "kerno")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, "./cmd/kerno")
	buildCmd.Dir = repoRoot

	output, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build kerno binary for runtime integration test: %v\n%s", err, output)
	}

	return binPath
}

func writeRuntimeConfig(t *testing.T) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	const configYAML = "prometheus:\n  enabled: true\n"

	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("write runtime integration config: %v", err)
	}

	return configPath
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback address: %v", err)
	}
	defer ln.Close()

	return ln.Addr().String()
}

func waitForHealthz(t *testing.T, ctx context.Context, url string, waitCh <-chan error, stdout, stderr *bytes.Buffer) map[string]any {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}

	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("create healthz request: %v", err)
		}

		resp, err := client.Do(req)
		if err == nil {
			var body map[string]any
			decodeErr := json.NewDecoder(resp.Body).Decode(&body)
			closeErr := resp.Body.Close()
			if resp.StatusCode == http.StatusOK && decodeErr == nil && closeErr == nil {
				return body
			}
		}

		select {
		case waitErr := <-waitCh:
			t.Fatalf("kerno runtime command exited before healthz became ready: %v\nstdout:\n%s\nstderr:\n%s", waitErr, stdout.String(), stderr.String())
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s: %v\nstdout:\n%s\nstderr:\n%s", url, ctx.Err(), stdout.String(), stderr.String())
		case <-time.After(250 * time.Millisecond):
		}
	}
}
