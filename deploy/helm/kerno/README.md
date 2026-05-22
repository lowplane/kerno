# Kerno Helm Chart

Deploys Kerno as a DaemonSet.

## Installation

```bash
helm install kerno ./deploy/helm/kerno -n kerno-system --create-namespace
```

## Hardening

Set `networkPolicy.enabled=true` to restrict metrics and debug ingress to Prometheus pods, allow DNS/Kubelet/API server egress, and deny other traffic.
