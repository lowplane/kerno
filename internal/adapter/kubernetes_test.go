// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"fmt"
	"log/slog"
	"sort"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const podCount = 1000

// makeFakePods builds n synthetic pods, each with one container and a unique
// container ID. UIDs and container IDs are deterministic so tests are stable.
func makeFakePods(n int) []*corev1.Pod {
	pods := make([]*corev1.Pod, n)
	for i := 0; i < n; i++ {
		uid := fmt.Sprintf("%08x-0000-0000-0000-%012x", i, i)
		// Index in leading bytes so every 12-char prefix is unique.
		cid := fmt.Sprintf("%012x%052x", i, 0)
		pods[i] = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("pod-%d", i),
				Namespace: fmt.Sprintf("ns-%d", i%10),
				UID:       types.UID(uid),
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "ReplicaSet", Name: fmt.Sprintf("deploy-%d-abc123def", i%50)},
				},
			},
			Spec: corev1.PodSpec{NodeName: "test-node"},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:        "app",
						ContainerID: "containerd://" + cid,
					},
				},
			},
		}
	}
	return pods
}

// warmAdapter builds an adapter and indexes all pods.
func warmAdapter(pods []*corev1.Pod) *KubernetesAdapter {
	a := NewKubernetesAdapter(slog.Default())
	for _, pod := range pods {
		a.addPod(pod)
	}
	return a
}

// TestKubernetesAdapter_CorrectnessUID verifies every pod is resolvable by UID.
func TestKubernetesAdapter_CorrectnessUID(t *testing.T) {
	pods := makeFakePods(podCount)
	a := warmAdapter(pods)

	for _, pod := range pods {
		uid := string(pod.UID)
		info := a.LookupByUID(uid)
		if info == nil {
			t.Errorf("LookupByUID(%q) = nil", uid)
			continue
		}
		if info.Name != pod.Name {
			t.Errorf("LookupByUID(%q).Name = %q, want %q", uid, info.Name, pod.Name)
		}
	}
}

// TestKubernetesAdapter_CorrectnessCgroup verifies every pod is resolvable by
// its 12-character container ID prefix (the fragment embedded in cgroup paths).
func TestKubernetesAdapter_CorrectnessCgroup(t *testing.T) {
	pods := makeFakePods(podCount)
	a := warmAdapter(pods)

	for _, pod := range pods {
		cid := pod.Status.ContainerStatuses[0].ContainerID[len("containerd://"):]
		prefix := cid[:12]
		info := a.LookupByCgroup(prefix)
		if info == nil {
			t.Errorf("LookupByCgroup(%q) = nil for pod %s", prefix, pod.Name)
			continue
		}
		if info.Name != pod.Name {
			t.Errorf("LookupByCgroup(%q).Name = %q, want %q", prefix, info.Name, pod.Name)
		}
	}
}

// TestKubernetesAdapter_CorrectnessRemove verifies that deleted pods are no
// longer resolvable.
func TestKubernetesAdapter_CorrectnessRemove(t *testing.T) {
	pods := makeFakePods(10)
	a := warmAdapter(pods)

	target := pods[3]
	a.removePod(target)

	if info := a.LookupByUID(string(target.UID)); info != nil {
		t.Errorf("LookupByUID after removePod: expected nil, got %+v", info)
	}
	cid := target.Status.ContainerStatuses[0].ContainerID[len("containerd://"):]
	if info := a.LookupByCgroup(cid[:12]); info != nil {
		t.Errorf("LookupByCgroup after removePod: expected nil, got %+v", info)
	}

	// Other pods must still be resolvable.
	for i, pod := range pods {
		if i == 3 {
			continue
		}
		if info := a.LookupByUID(string(pod.UID)); info == nil {
			t.Errorf("pod %d unexpectedly missing after unrelated remove", i)
		}
	}
}

// TestKubernetesAdapter_LookupByPath exercises the PodLookup interface using
// cgroup v1 and cgroup v2 / systemd path formats.
func TestKubernetesAdapter_LookupByPath(t *testing.T) {
	pods := makeFakePods(5)
	a := warmAdapter(pods)

	pod := pods[0]
	uid := string(pod.UID)
	uidUnderscore := replaceAll(uid, "-", "_")

	tests := []struct {
		name  string
		path  string
		wantP string
	}{
		{
			"cgroup v1",
			"/kubepods/burstable/pod" + uid + "/abc123",
			pod.Name,
		},
		{
			"cgroup v2 systemd",
			"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uidUnderscore + ".slice/cri-containerd-xyz.scope",
			pod.Name,
		},
		{
			"no match",
			"/system.slice/nginx.service",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPod, _ := a.LookupByPath(tt.path)
			if gotPod != tt.wantP {
				t.Errorf("LookupByPath(%q) pod = %q, want %q", tt.path, gotPod, tt.wantP)
			}
		})
	}
}

// replaceAll is strings.ReplaceAll kept local to avoid importing strings just
// for the test helper.
func replaceAll(s, from, to string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if i+len(from) <= len(s) && s[i:i+len(from)] == from {
			out = append(out, to...)
			i += len(from)
		} else {
			out = append(out, s[i])
			i++
		}
	}
	return string(out)
}

// TestKubernetesAdapter_LookupLatency asserts p99 < 10µs for both lookup types
// after cache warmup with podCount pods. Each lookup is a single RLock + map
// read + RUnlock.
func TestKubernetesAdapter_LookupLatency(t *testing.T) {
	pods := makeFakePods(podCount)
	a := warmAdapter(pods)

	uids := make([]string, podCount)
	prefixes := make([]string, podCount)
	for i, pod := range pods {
		uids[i] = string(pod.UID)
		cid := pod.Status.ContainerStatuses[0].ContainerID[len("containerd://"):]
		prefixes[i] = cid[:12]
	}

	const warmupRuns = 5
	const measuredRuns = podCount

	// UID lookup latency.
	uidLatencies := make([]time.Duration, measuredRuns)
	for w := 0; w < warmupRuns; w++ {
		for _, uid := range uids {
			a.LookupByUID(uid)
		}
	}
	for i, uid := range uids {
		start := time.Now()
		a.LookupByUID(uid)
		uidLatencies[i] = time.Since(start)
	}
	sort.Slice(uidLatencies, func(i, j int) bool { return uidLatencies[i] < uidLatencies[j] })
	p99uid := uidLatencies[int(float64(measuredRuns)*0.99)]
	if p99uid > 10*time.Microsecond {
		t.Errorf("LookupByUID p99 = %v, want < 10µs", p99uid)
	}

	// Cgroup lookup latency.
	cgroupLatencies := make([]time.Duration, measuredRuns)
	for w := 0; w < warmupRuns; w++ {
		for _, pfx := range prefixes {
			a.LookupByCgroup(pfx)
		}
	}
	for i, pfx := range prefixes {
		start := time.Now()
		a.LookupByCgroup(pfx)
		cgroupLatencies[i] = time.Since(start)
	}
	sort.Slice(cgroupLatencies, func(i, j int) bool { return cgroupLatencies[i] < cgroupLatencies[j] })
	p99cg := cgroupLatencies[int(float64(measuredRuns)*0.99)]
	if p99cg > 10*time.Microsecond {
		t.Errorf("LookupByCgroup p99 = %v, want < 10µs", p99cg)
	}
}
