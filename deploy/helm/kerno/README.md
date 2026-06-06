# Kerno Helm Chart

Kerno is an eBPF-based kernel observability engine for Kubernetes. It diagnoses production incidents by watching kernel signals (disk, TCP, OOM, scheduler) and providing a ranked diagnostic report.

## Prerequisites

- Kubernetes 1.22+
- Helm 3.8.0+
- Linux kernel 5.8+ with BTF enabled (standard on EKS, GKE, AKS, etc.)

## Installation

```bash
helm repo add kerno https://optiqor.github.io/kerno-charts
helm repo update
helm install kerno kerno/kerno -n kerno-system --create-namespace
```

## Configuration

The following table lists the most common configurable parameters of the Kerno chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Image repository | `ghcr.io/optiqor/kerno` |
| `image.tag` | Image tag | `{{ .Chart.AppVersion }}` |
| `resources.requests.cpu` | CPU requests | `100m` |
| `resources.requests.memory` | Memory requests | `128Mi` |
| `prometheus.enabled` | Enable Prometheus metrics | `true` |
| `collectors.syscallLatency` | Enable syscall latency collector | `true` |
| `collectors.tcpMonitor` | Enable TCP monitor collector | `true` |
| `collectors.oomTrack` | Enable OOM tracker | `true` |
| `collectors.diskIO` | Enable Disk I/O collector | `true` |
| `collectors.schedDelay` | Enable scheduler delay collector | `true` |
| `collectors.fdTrack` | Enable file descriptor tracker | `true` |

For a full list of parameters, see [values.yaml](values.yaml).

## Examples

### Enable AI Diagnosis
```bash
helm install kerno kerno/kerno \
  --set extraEnv[0].name=KERNO_AI_API_KEY \
  --set extraEnv[0].value=your-key \
  --set extraEnv[1].name=KERNO_AI_PROVIDER \
  --set extraEnv[1].value=anthropic
```

## Version Compatibility Matrix

| Kerno Version | K8s Version | Kernel Version |
|---------------|-------------|----------------|
| v0.1.x        | 1.22 - 1.31 | 5.8+           |
