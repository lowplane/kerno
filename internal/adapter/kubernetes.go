// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesAdapter enriches events with pod metadata using a SharedIndexInformer
// scoped to the local node via spec.nodeName field selector.
//
// Architecture:
//   - Start() launches a goroutine that builds a clientset (in-cluster auth,
//     kubeconfig fallback) and runs a SharedIndexInformer filtered to the node.
//   - The informer populates two in-memory indexes: uidIndex and cgroupIndex.
//   - If the API server is unreachable the goroutine retries with exponential
//     backoff; stale index entries are kept so enrichment continues degraded.
//   - IsReady() returns true once the initial cache sync completes.
type KubernetesAdapter struct {
	logger   *slog.Logger
	nodeName string
	hostname string

	mu          sync.RWMutex
	uidIndex    map[string]*PodInfo // pod UID → PodInfo
	cgroupIndex map[string]*PodInfo // cgroup fragment → PodInfo

	ready    atomic.Bool
	cancelFn context.CancelFunc
}

// PodInfo holds the K8s metadata extracted for a pod.
type PodInfo struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Node       string `json:"node"`
	Deployment string `json:"deployment,omitempty"`
	UID        string `json:"uid"`
}

// NewKubernetesAdapter creates a Kubernetes adapter. It reads NODE_NAME from
// the environment (Downward API injection), falling back to KERNO_NODE_NAME,
// then os.Hostname().
func NewKubernetesAdapter(logger *slog.Logger) *KubernetesAdapter {
	hostname, _ := os.Hostname()
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = os.Getenv("KERNO_NODE_NAME")
	}
	if nodeName == "" {
		nodeName = hostname
	}
	return &KubernetesAdapter{
		logger:      logger,
		nodeName:    nodeName,
		hostname:    hostname,
		uidIndex:    make(map[string]*PodInfo),
		cgroupIndex: make(map[string]*PodInfo),
	}
}

func (a *KubernetesAdapter) Name() string { return "kubernetes" }

// IsReady returns true once the informer cache has completed its initial sync.
func (a *KubernetesAdapter) IsReady() bool { return a.ready.Load() }

func (a *KubernetesAdapter) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	a.cancelFn = cancel
	go a.runWithBackoff(ctx)
	return nil
}

func (a *KubernetesAdapter) Stop() {
	if a.cancelFn != nil {
		a.cancelFn()
	}
}

func (a *KubernetesAdapter) runWithBackoff(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 2 * time.Minute

	for {
		if err := a.run(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			a.ready.Store(false)
			a.logger.Warn("kubernetes informer stopped, retrying",
				"error", err,
				"backoff", backoff,
			)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, maxBackoff)
		} else {
			return
		}
	}
}

func (a *KubernetesAdapter) run(ctx context.Context) error {
	cs, err := buildClientset()
	if err != nil {
		return fmt.Errorf("build clientset: %w", err)
	}

	fieldSel := fields.OneTermEqualSelector("spec.nodeName", a.nodeName).String()
	factory := informers.NewSharedInformerFactoryWithOptions(
		cs,
		0,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fieldSel
		}),
	)

	podInformer := factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{ //nolint:errcheck
		AddFunc: func(obj any) {
			if pod, ok := obj.(*corev1.Pod); ok {
				a.addPod(pod)
			}
		},
		UpdateFunc: func(old, updated any) {
			if oldPod, ok := old.(*corev1.Pod); ok {
				a.removePod(oldPod)
			}
			if pod, ok := updated.(*corev1.Pod); ok {
				a.addPod(pod)
			}
		},
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				ts, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				pod, ok = ts.Obj.(*corev1.Pod)
				if !ok {
					return
				}
			}
			a.removePod(pod)
		},
	})

	stopCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stopCh)
	}()

	factory.Start(stopCh)
	a.logger.Info("kubernetes informer starting", "node", a.nodeName)

	if !cache.WaitForCacheSync(stopCh, podInformer.HasSynced) {
		select {
		case <-stopCh:
			return nil // context canceled — clean shutdown
		default:
			return fmt.Errorf("informer cache sync failed")
		}
	}

	a.ready.Store(true)
	a.logger.Info("kubernetes informer synced", "node", a.nodeName)

	<-stopCh
	return nil
}

// buildClientset constructs a clientset using in-cluster auth when available,
// falling back to KUBECONFIG / ~/.kube/config for local development.
func buildClientset() (*kubernetes.Clientset, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			if home, herr := os.UserHomeDir(); herr == nil {
				kubeconfig = home + "/.kube/config"
			}
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("kubeconfig: %w", err)
		}
	}
	return kubernetes.NewForConfig(cfg)
}

// addPod inserts or replaces the index entries for a pod.
func (a *KubernetesAdapter) addPod(pod *corev1.Pod) {
	info := podInfoFromK8s(pod)
	uid := string(pod.UID)

	a.mu.Lock()
	defer a.mu.Unlock()

	a.uidIndex[uid] = info
	a.cgroupIndex[uid] = info
	// Systemd cgroup v2 driver escapes dashes to underscores.
	a.cgroupIndex[strings.ReplaceAll(uid, "-", "_")] = info

	for _, cs := range pod.Status.ContainerStatuses {
		a.indexContainerID(cs.ContainerID, info)
	}
	for _, cs := range pod.Status.InitContainerStatuses {
		a.indexContainerID(cs.ContainerID, info)
	}
}

// removePod deletes all index entries for a pod.
func (a *KubernetesAdapter) removePod(pod *corev1.Pod) {
	uid := string(pod.UID)

	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.uidIndex, uid)
	delete(a.cgroupIndex, uid)
	delete(a.cgroupIndex, strings.ReplaceAll(uid, "-", "_"))

	for _, cs := range pod.Status.ContainerStatuses {
		a.unindexContainerID(cs.ContainerID)
	}
	for _, cs := range pod.Status.InitContainerStatuses {
		a.unindexContainerID(cs.ContainerID)
	}
}

// indexContainerID adds container ID entries to cgroupIndex. Must be called
// with a.mu held.
func (a *KubernetesAdapter) indexContainerID(ref string, info *PodInfo) {
	cid := stripRuntimePrefix(ref)
	if cid == "" {
		return
	}
	a.cgroupIndex[cid] = info
	if len(cid) >= 12 {
		a.cgroupIndex[cid[:12]] = info
	}
}

// unindexContainerID removes container ID entries from cgroupIndex. Must be
// called with a.mu held.
func (a *KubernetesAdapter) unindexContainerID(ref string) {
	cid := stripRuntimePrefix(ref)
	if cid == "" {
		return
	}
	delete(a.cgroupIndex, cid)
	if len(cid) >= 12 {
		delete(a.cgroupIndex, cid[:12])
	}
}

// stripRuntimePrefix strips the "containerd://", "docker://", etc. prefix
// from a container ID reference.
func stripRuntimePrefix(ref string) string {
	if i := strings.LastIndex(ref, "//"); i >= 0 {
		return ref[i+2:]
	}
	return ref
}

func podInfoFromK8s(pod *corev1.Pod) *PodInfo {
	info := &PodInfo{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Node:      pod.Spec.NodeName,
		UID:       string(pod.UID),
	}
	for _, ref := range pod.OwnerReferences {
		if ref.Kind == "ReplicaSet" {
			info.Deployment = extractDeploymentName(ref.Name)
			break
		}
	}
	if info.Deployment == "" {
		if d, ok := pod.Labels["app"]; ok {
			info.Deployment = d
		}
	}
	return info
}

// LookupByUID returns the PodInfo for the given pod UID, or nil if not found.
func (a *KubernetesAdapter) LookupByUID(uid string) *PodInfo {
	a.mu.RLock()
	info := a.uidIndex[uid]
	a.mu.RUnlock()
	return info
}

// LookupByCgroup looks up a pod by a cgroup fragment — pod UID variant
// (dashes or underscores) or container ID (full 64-char hex or 12-char prefix).
func (a *KubernetesAdapter) LookupByCgroup(fragment string) *PodInfo {
	a.mu.RLock()
	info := a.cgroupIndex[fragment]
	a.mu.RUnlock()
	return info
}

// LookupByPath resolves a cgroup path to a pod name and namespace.
// Implements collector.PodLookup.
func (a *KubernetesAdapter) LookupByPath(cgroupPath string) (pod, namespace string) {
	uid := extractPodUID(cgroupPath)
	if uid == "" {
		return "", ""
	}
	info := a.LookupByUID(uid)
	if info == nil {
		info = a.LookupByCgroup(strings.ReplaceAll(uid, "-", "_"))
	}
	if info == nil {
		return "", ""
	}
	return info.Name, info.Namespace
}

// Enrich maps the cgroup path to K8s pod metadata. Stale index entries are
// preserved across API server disconnects so enrichment continues degraded.
func (a *KubernetesAdapter) Enrich(meta *EventMeta) {
	meta.Hostname = a.hostname
	meta.Node = a.nodeName

	if meta.PID > 0 && meta.CgroupPath == "" {
		meta.CgroupPath = cgroupPathForPID(meta.PID)
	}
	if meta.CgroupPath == "" {
		return
	}

	uid := extractPodUID(meta.CgroupPath)
	if uid == "" {
		return
	}

	info := a.LookupByUID(uid)
	if info == nil {
		info = a.LookupByCgroup(strings.ReplaceAll(uid, "-", "_"))
	}
	if info != nil {
		meta.Pod = info.Name
		meta.Namespace = info.Namespace
		meta.Node = info.Node
		meta.Deployment = info.Deployment
	}
}

// extractPodUID extracts a Kubernetes pod UID from a cgroup path.
//
// cgroup v1: /kubepods/burstable/pod<uid>/<container-id>
// cgroup v2 / systemd: /kubepods.slice/.../kubepods-burstable-pod<uid_with_underscores>.slice/...
func extractPodUID(cgroupPath string) string {
	// cgroup v1 style: ".../pod<uid>/..."
	if idx := strings.Index(cgroupPath, "/pod"); idx >= 0 {
		rest := cgroupPath[idx+4:]
		end := strings.IndexByte(rest, '/')
		if end < 0 {
			end = len(rest)
		}
		uid := rest[:end]
		if isUIDLike(uid) {
			return uid
		}
	}

	// cgroup v2 / systemd style: "...-pod<uid>.slice"
	if podIdx := strings.Index(cgroupPath, "-pod"); podIdx >= 0 {
		rest := cgroupPath[podIdx+4:]
		end := strings.IndexByte(rest, '.')
		if end < 0 {
			end = len(rest)
		}
		uid := strings.ReplaceAll(rest[:end], "_", "-")
		if isUIDLike(uid) {
			return uid
		}
	}

	return ""
}

// isUIDLike checks if s looks like a Kubernetes UID (UUID-ish hex string).
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

// extractDeploymentName strips the trailing hash from a ReplicaSet name to
// recover the parent Deployment name.
func extractDeploymentName(replicaSetName string) string {
	lastDash := strings.LastIndex(replicaSetName, "-")
	if lastDash <= 0 {
		return replicaSetName
	}
	return replicaSetName[:lastDash]
}
