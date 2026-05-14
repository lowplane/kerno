// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// KubernetesAdapter enriches events with pod metadata by mapping
// cgroup paths to pod names/namespaces via the Kubelet read-only API.
//
// Architecture:
//   - On Start(), it fetches the pod list from the local Kubelet API
//     and builds a cgroup-to-pod index (map[string]*PodInfo).
//   - The index is refreshed periodically (default 30s) to track new pods.
//   - Enrich() looks up the PID's cgroup path in the index.
//   - No dependency on client-go — uses raw HTTP to the Kubelet.
type KubernetesAdapter struct {
	logger   *slog.Logger
	hostname string
	nodeName string

	mu    sync.RWMutex
	index map[string]*PodInfo // cgroup path suffix → pod info

	client      *http.Client
	kubeletURL  string
	refreshRate time.Duration
	cancelFn    context.CancelFunc
}

// PodInfo holds the K8s metadata extracted for a pod.
type PodInfo struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Node       string `json:"node"`
	Deployment string `json:"deployment,omitempty"`
	UID        string `json:"uid"`
}

// NewKubernetesAdapter creates a Kubernetes adapter.
func NewKubernetesAdapter(logger *slog.Logger) *KubernetesAdapter {
	hostname, _ := os.Hostname()
	nodeName := os.Getenv("KERNO_NODE_NAME")
	if nodeName == "" {
		nodeName = hostname
	}

	return &KubernetesAdapter{
		logger:      logger,
		hostname:    hostname,
		nodeName:    nodeName,
		index:       make(map[string]*PodInfo),
		client:      &http.Client{Timeout: 5 * time.Second},
		kubeletURL:  kubeletReadOnlyURL(),
		refreshRate: 30 * time.Second,
	}
}

func (a *KubernetesAdapter) Name() string { return "kubernetes" }

func (a *KubernetesAdapter) Start(ctx context.Context) error {
	a.logger.Info("kubernetes adapter starting",
		"node", a.nodeName,
		"kubeletURL", a.kubeletURL,
	)

	ctx, cancel := context.WithCancel(ctx)

	// Initial index build with retries.
	if err := a.refreshIndex(ctx); err != nil {
		a.logger.Warn("initial pod index build failed, will retry",
			"error", err,
		)
	}
	a.cancelFn = cancel

	go a.refreshLoop(ctx)

	a.logger.Info("kubernetes adapter started", "pods", len(a.index))
	return nil
}

func (a *KubernetesAdapter) Stop() {
	if a.cancelFn != nil {
		a.cancelFn()
	}
}

// LookupByPath resolves a cgroup path to a Kubernetes pod name and namespace.
// Returns ("", "") when the path cannot be matched (non-K8s or unknown pod).
// Implements collector.PodLookup.
func (a *KubernetesAdapter) LookupByPath(cgroupPath string) (pod, namespace string) {
	uid := extractPodUID(cgroupPath)
	if uid == "" {
		return "", ""
	}
	a.mu.RLock()
	info, ok := a.index[uid]
	a.mu.RUnlock()
	if !ok {
		return "", ""
	}
	return info.Name, info.Namespace
}

// Enrich maps the PID's cgroup path to a K8s pod and populates metadata.
func (a *KubernetesAdapter) Enrich(meta *EventMeta) {
	meta.Hostname = a.hostname
	meta.Node = a.nodeName

	if meta.PID > 0 && meta.CgroupPath == "" {
		meta.CgroupPath = cgroupPathForPID(meta.PID)
	}
	if meta.CgroupPath == "" {
		return
	}

	// Extract pod UID from cgroup path.
	uid := extractPodUID(meta.CgroupPath)
	if uid == "" {
		return
	}

	a.mu.RLock()
	info, ok := a.index[uid]
	a.mu.RUnlock()

	if ok {
		meta.Pod = info.Name
		meta.Namespace = info.Namespace
		meta.Node = info.Node
		meta.Deployment = info.Deployment
	}
}

// refreshLoop periodically refreshes the pod index.
func (a *KubernetesAdapter) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(a.refreshRate)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.refreshIndex(ctx); err != nil {
				a.logger.Debug("pod index refresh failed", "error", err)
			}
		}
	}
}

// refreshIndex fetches the pod list from Kubelet and rebuilds the index.
func (a *KubernetesAdapter) refreshIndex(ctx context.Context) error {
	pods, err := a.fetchPods(ctx)
	if err != nil {
		return err
	}

	newIndex := make(map[string]*PodInfo, len(pods))
	for _, pod := range pods {
		newIndex[pod.UID] = pod
	}

	a.mu.Lock()
	a.index = newIndex
	a.mu.Unlock()

	a.logger.Debug("pod index refreshed", "pods", len(newIndex))
	return nil
}

// kubeletPodList is the minimal structure for Kubelet /pods response.
type kubeletPodList struct {
	Items []kubeletPod `json:"items"`
}

type kubeletPod struct {
	Metadata kubeletMeta `json:"metadata"`
	Spec     kubeletSpec `json:"spec"`
}

type kubeletMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	UID             string            `json:"uid"`
	OwnerReferences []kubeletOwnerRef `json:"ownerReferences,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
}

type kubeletSpec struct {
	NodeName string `json:"nodeName"`
}

type kubeletOwnerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// fetchPods retrieves the pod list from the Kubelet read-only API.
func (a *KubernetesAdapter) fetchPods(ctx context.Context) ([]*PodInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.kubeletURL+"/pods", nil)
	if err != nil {
		return nil, fmt.Errorf("kubelet request build: %w", err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kubelet request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kubelet returned %d", resp.StatusCode)
	}

	var podList kubeletPodList
	if err := json.NewDecoder(resp.Body).Decode(&podList); err != nil {
		return nil, fmt.Errorf("decoding kubelet response: %w", err)
	}

	pods := make([]*PodInfo, 0, len(podList.Items))
	for _, item := range podList.Items {
		info := &PodInfo{
			Name:      item.Metadata.Name,
			Namespace: item.Metadata.Namespace,
			Node:      item.Spec.NodeName,
			UID:       item.Metadata.UID,
		}

		// Extract deployment name from ownerReferences or labels.
		for _, ref := range item.Metadata.OwnerReferences {
			if ref.Kind == "ReplicaSet" {
				// ReplicaSet name is typically <deployment>-<hash>.
				info.Deployment = extractDeploymentName(ref.Name)
				break
			}
		}
		if info.Deployment == "" {
			if d, ok := item.Metadata.Labels["app"]; ok {
				info.Deployment = d
			}
		}

		pods = append(pods, info)
	}

	return pods, nil
}

// kubeletReadOnlyURL returns the Kubelet read-only API endpoint.
// Default port is 10255 unless overridden by env var.
func kubeletReadOnlyURL() string {
	if url := os.Getenv("KERNO_KUBELET_URL"); url != "" {
		return url
	}
	return "http://localhost:10255"
}

// extractPodUID extracts a Kubernetes pod UID from a cgroup path.
//
// cgroup v2 examples:
//
//	/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<cid>.scope
//	/kubepods/burstable/pod<uid>/<container-id>
//
// cgroup v1 examples:
//
//	/kubepods/burstable/pod<uid>/<container-id>
//	/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<uid>.slice
func extractPodUID(cgroupPath string) string {
	// Look for "pod" followed by a UUID-like string.
	// Common patterns:
	//   pod<uid>/                     (cgroup v1)
	//   kubepods-*-pod<uid>.slice     (cgroup v2 / systemd driver)

	// Try cgroup v1 style: ".../pod<uid>/..."
	idx := strings.Index(cgroupPath, "/pod")
	if idx >= 0 {
		rest := cgroupPath[idx+4:] // skip "/pod"
		// UID goes until next '/' or end.
		end := strings.IndexByte(rest, '/')
		if end < 0 {
			end = len(rest)
		}
		uid := rest[:end]
		if isUIDLike(uid) {
			return uid
		}
	}

	// Try cgroup v2 / systemd style: "...-pod<uid>.slice"
	podIdx := strings.Index(cgroupPath, "-pod")
	if podIdx >= 0 {
		rest := cgroupPath[podIdx+4:] // skip "-pod"
		end := strings.IndexByte(rest, '.')
		if end < 0 {
			end = len(rest)
		}
		uid := rest[:end]
		// Systemd escapes dashes: replace '_' with '-' in UID.
		uid = strings.ReplaceAll(uid, "_", "-")
		if isUIDLike(uid) {
			return uid
		}
	}

	return ""
}

// isUIDLike checks if a string looks like a Kubernetes UID (UUID format).
// We're lenient — just check length and allowed characters.
func isUIDLike(s string) bool {
	if len(s) < 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// extractDeploymentName extracts the deployment name from a ReplicaSet name.
// ReplicaSet names follow the pattern <deployment>-<hash>.
func extractDeploymentName(replicaSetName string) string {
	lastDash := strings.LastIndex(replicaSetName, "-")
	if lastDash <= 0 {
		return replicaSetName
	}
	return replicaSetName[:lastDash]
}
