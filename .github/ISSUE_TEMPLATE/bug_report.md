---
name: Bug Report
about: Report a bug to help improve Kerno
title: "[BUG] "
labels: bug
assignees: ''
---

## Describe the Bug

A clear and concise description of what the bug is.

## To Reproduce

Steps to reproduce the behavior:

1. Run `kerno ...`
2. Observe ...
3. See error

## Expected Behavior

A clear description of what you expected to happen.

## Environment

- **Kerno version:** (`kerno version`)
- **Kernel version:** (`uname -r`)
- **Linux distribution:** (`cat /etc/os-release | head -3`)
- **Architecture:** (`uname -m`)
- **Go version:** (`go version`) *(if building from source)*
- **Running in Kubernetes?** Yes / No
  - **K8s version:** (`kubectl version --short`)

## Logs

```
Paste relevant kerno logs here.
Run with --log-level debug for verbose output.
```

## BPF Verifier Output (if applicable)

```
Paste verifier log here, if the error is related to eBPF program loading.
```

## Additional Context

Add any other context about the problem here.
