# Kerno Helm Chart

Deploys Kerno as a DaemonSet.

## Installation

```bash
helm install kerno ./deploy/helm/kerno -n kerno-system --create-namespace
```

## Hardening

Set `networkPolicy.enabled=true` to enable the NetworkPolicy.

> [!WARNING]
> Since Kerno runs with `hostNetwork: true`, standard Kubernetes `NetworkPolicy` resources are not enforced on it by most mainstream CNIs (like Cilium or Calico) without host-endpoint or host-firewall configuration.
>
> If `networkPolicy.enabled` is set to `true`, egress to the Kubernetes API server and Kubelet is blocked by default unless their specific IP CIDR blocks are configured via `networkPolicy.k8sApiServer.cidrs` and `networkPolicy.kubelet.cidrs` respectively.

