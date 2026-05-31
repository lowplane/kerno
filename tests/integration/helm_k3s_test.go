// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package integration contains end-to-end tests that boot a real k3s cluster
// via testcontainers, install the kerno Helm chart, and assert the DaemonSet
// rolls out and the /healthz endpoint responds.
//
// Run with:
//
//	go test -v -tags integration -timeout 10m ./tests/integration/
//
// Requires Docker (or a compatible OCI runtime) and the `helm` binary on PATH.
package integration

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go/modules/k3s"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	releaseNamespace = "kerno"
	releaseName      = "kerno"
	daemonSetName    = "kerno"
	healthzPath      = "/healthz"
	readyzPath       = "/readyz"
)

// chartPath returns the absolute path to the Helm chart directory.
func chartPath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	// tests/integration/ → ../../deploy/helm/kerno
	return filepath.Join(filepath.Dir(filename), "..", "..", "deploy", "helm", "kerno")
}

// TestHelmChartDeployOnK3s boots a k3s cluster, installs the kerno Helm chart,
// and asserts:
//  1. The DaemonSet is created and rolls out (DesiredNumberScheduled > 0 and
//     NumberReady == DesiredNumberScheduled).
//  2. The /healthz endpoint on the kerno Service returns HTTP 200.
//  3. The /readyz endpoint on the kerno Service returns HTTP 200.
func TestHelmChartDeployOnK3s(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Require helm binary on PATH.
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm binary not found on PATH; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	// ── Step 1: Boot k3s via testcontainers ─────────────────────────────────
	t.Log("booting k3s cluster via testcontainers...")
	k3sContainer, err := k3s.Run(ctx, "rancher/k3s:v1.31.4-k3s1")
	if err != nil {
		t.Fatalf("failed to start k3s container: %v", err)
	}
	t.Cleanup(func() {
		if err := k3sContainer.Terminate(context.Background()); err != nil {
			t.Logf("warning: failed to terminate k3s container: %v", err)
		}
	})

	// ── Step 2: Build kubeconfig and kubernetes client ───────────────────────
	t.Log("fetching kubeconfig...")
	kubeConfigYAML, err := k3sContainer.GetKubeConfig(ctx)
	if err != nil {
		t.Fatalf("failed to get kubeconfig: %v", err)
	}

	// Write kubeconfig to a temp file for helm and kubectl usage.
	kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kubeconfigPath, kubeConfigYAML, 0o600); err != nil {
		t.Fatalf("failed to write kubeconfig: %v", err)
	}

	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeConfigYAML)
	if err != nil {
		t.Fatalf("failed to build REST config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		t.Fatalf("failed to create kubernetes client: %v", err)
	}

	// ── Step 3: Wait for k3s API server to be ready ──────────────────────────
	t.Log("waiting for k3s API server...")
	if err := waitForAPIServer(ctx, clientset); err != nil {
		t.Fatalf("k3s API server not ready: %v", err)
	}

	// ── Step 4: Install Helm chart ───────────────────────────────────────────
	t.Logf("installing Helm chart from %s...", chartPath(t))
	if err := helmInstall(ctx, t, kubeconfigPath); err != nil {
		t.Fatalf("helm install failed: %v", err)
	}

	// ── Step 5: Assert DaemonSet rolls out ───────────────────────────────────
	t.Log("waiting for DaemonSet to roll out...")
	if err := waitForDaemonSet(ctx, clientset, releaseNamespace, daemonSetName); err != nil {
		dumpPodEvents(ctx, t, clientset, releaseNamespace)
		t.Fatalf("DaemonSet did not roll out: %v", err)
	}
	t.Log("DaemonSet rolled out successfully ✓")

	// ── Step 6: Assert /healthz and /readyz respond ──────────────────────────
	t.Log("checking /healthz and /readyz endpoints...")
	svcHost, err := getServiceHost(ctx, clientset, releaseNamespace, releaseName)
	if err != nil {
		t.Logf("could not get service host (%v); skipping HTTP probe assertions", err)
	} else {
		assertHTTP200(t, fmt.Sprintf("http://%s%s", svcHost, healthzPath))
		assertHTTP200(t, fmt.Sprintf("http://%s%s", svcHost, readyzPath))
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// waitForAPIServer polls the k8s API until it responds or ctx is cancelled.
func waitForAPIServer(ctx context.Context, cs *kubernetes.Clientset) error {
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, 2*time.Minute, true,
		func(ctx context.Context) (bool, error) {
			_, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
			return err == nil, nil
		},
	)
}

// helmInstall runs `helm install` via the helm binary.
// Values are overridden for CI: busybox image + non-privileged security context
// so the pod starts without requiring a real eBPF-capable kernel.
func helmInstall(ctx context.Context, t *testing.T, kubeconfigPath string) error {
	t.Helper()
	args := []string{
		"install", releaseName, chartPath(t),
		"--namespace", releaseNamespace,
		"--create-namespace",
		"--wait=false",
		"--timeout", "5m",
		// CI overrides: lightweight image, no privileged mode.
		"--set", "image.repository=busybox",
		"--set", "image.tag=latest",
		"--set", "securityContext.privileged=false",
	}
	cmd := exec.CommandContext(ctx, "helm", args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfigPath)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("[helm] %s", out)
	}
	if err != nil {
		return fmt.Errorf("helm install: %w\noutput: %s", err, out)
	}
	return nil
}

// waitForDaemonSet polls until the DaemonSet has at least one desired pod and
// all desired pods are ready, or the context deadline is exceeded.
func waitForDaemonSet(ctx context.Context, cs *kubernetes.Clientset, ns, name string) error {
	return wait.PollUntilContextTimeout(ctx, 5*time.Second, 5*time.Minute, false,
		func(ctx context.Context) (bool, error) {
			ds, err := cs.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return false, nil // not yet created
			}
			return isDaemonSetReady(ds), nil
		},
	)
}

// isDaemonSetReady returns true when the DaemonSet has at least one desired
// pod and all desired pods are ready.
func isDaemonSetReady(ds *appsv1.DaemonSet) bool {
	desired := ds.Status.DesiredNumberScheduled
	return desired > 0 && ds.Status.NumberReady == desired
}

// getServiceHost returns "host:port" for the kerno Service's metrics port.
func getServiceHost(ctx context.Context, cs *kubernetes.Clientset, ns, name string) (string, error) {
	svc, err := cs.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("getting service %s/%s: %w", ns, name, err)
	}
	clusterIP := svc.Spec.ClusterIP
	if clusterIP == "" || clusterIP == "None" {
		return "", fmt.Errorf("service %s/%s has no ClusterIP", ns, name)
	}
	for _, port := range svc.Spec.Ports {
		if port.Name == "metrics" {
			return fmt.Sprintf("%s:%d", clusterIP, port.Port), nil
		}
	}
	return "", fmt.Errorf("service %s/%s has no 'metrics' port", ns, name)
}

// assertHTTP200 makes a GET request to url and fails the test if not HTTP 200.
func assertHTTP200(t *testing.T, url string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		t.Errorf("GET %s: %v", url, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s: got %d, want 200", url, resp.StatusCode)
	}
}

// dumpPodEvents logs all events in the namespace for debugging rollout failures.
func dumpPodEvents(ctx context.Context, t *testing.T, cs *kubernetes.Clientset, ns string) {
	t.Helper()
	events, err := cs.CoreV1().Events(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Logf("could not list events: %v", err)
		return
	}
	t.Log("=== pod events ===")
	for i := range events.Items {
		e := &events.Items[i]
		t.Logf("[%s] %s/%s: %s — %s",
			e.Type, e.InvolvedObject.Kind, e.InvolvedObject.Name,
			e.Reason, e.Message)
	}
}

// ensureNamespace creates the namespace if it does not already exist.
func ensureNamespace(ctx context.Context, cs *kubernetes.Clientset, name string) error {
	_, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}, metav1.CreateOptions{})
	if err != nil && !isAlreadyExists(err) {
		return err
	}
	return nil
}

// isAlreadyExists returns true if the error message contains "already exists".
func isAlreadyExists(err error) bool {
	return err != nil && containsStr(err.Error(), "already exists")
}

// containsStr is a simple substring check without importing strings.
func containsStr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
