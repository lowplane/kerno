# Security Policy

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Kerno, please report it responsibly:

1. **Email:** Send a detailed report to **team.optiqor@gmail.com**
2. **Subject line:** `[SECURITY] Brief description of vulnerability`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

| Step | Timeframe |
|------|-----------|
| Acknowledgment of report | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Depends on severity |
| Security advisory publication | Upon fix release |

## Severity Classification

| Severity | Description | Example |
|----------|-------------|---------|
| **Critical** | Remote code execution, privilege escalation via eBPF | Malicious BPF program injection |
| **High** | Information disclosure of sensitive kernel data | Unfiltered memory contents in events |
| **Medium** | Denial of service, resource exhaustion | Ring buffer memory bomb |
| **Low** | Minor information leak, configuration issue | Verbose error messages exposing paths |

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Previous minor | ✅ (security fixes only) |
| Older | ❌ |

---

## Release Artifact Signing & Verification

Kerno uses **keyless Sigstore signing** for all release artifacts. No private key — signing is performed by the GitHub Actions OIDC identity and recorded in the public [Rekor](https://rekor.sigstore.dev) transparency log.

### Signing identity

| Field | Value |
|-------|-------|
| **OIDC issuer** | `https://token.actions.githubusercontent.com` |
| **Certificate identity (regexp)** | `^https://github\.com/optiqor/kerno/\.github/workflows/release\.yml@refs/tags/v` |
| **Transparency log** | Sigstore / Rekor (public instance) |
| **Key management** | Keyless — no private key; GitHub OIDC ephemeral cert |

### What is signed

| Artifact | How | Where |
|----------|-----|-------|
| Container image (`:v*` tag) | `cosign sign` | OCI registry + Rekor |
| Container image (`:latest` tag) | `cosign sign` | OCI registry + Rekor |
| `checksums.txt` (covers all binaries & archives) | `cosign sign-blob` | Release assets (`.sig` + `.pem`) |
| CycloneDX SBOM | `cosign attest --type cyclonedx` | OCI registry + Rekor |

### Verify a container image

```bash
cosign verify ghcr.io/optiqor/kerno:v0.1.0 \
  --certificate-identity-regexp '^https://github\.com/optiqor/kerno/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Verify binary checksums

```bash
VERSION=v0.1.0
BASE=https://github.com/optiqor/kerno/releases/download/${VERSION}

curl -fsSL ${BASE}/checksums.txt     -o checksums.txt
curl -fsSL ${BASE}/checksums.txt.sig -o checksums.txt.sig
curl -fsSL ${BASE}/checksums.txt.pem -o checksums.txt.pem

cosign verify-blob checksums.txt \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  --certificate-identity-regexp '^https://github\.com/optiqor/kerno/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

curl -fsSL ${BASE}/kerno_${VERSION}_linux_amd64.tar.gz -o kerno.tar.gz
sha256sum --check --ignore-missing checksums.txt
```

### Verify the SBOM attestation

```bash
cosign verify-attestation ghcr.io/optiqor/kerno:v0.1.0 \
  --type cyclonedx \
  --certificate-identity-regexp '^https://github\.com/optiqor/kerno/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq '.payload | @base64d | fromjson | .predicate.metadata'
```

### Reporting a tampered artifact

Agar `cosign verify` fail ho kisi official release tag pe — **artifact use mat karo** aur turant report karo:

1. Email karo **team.optiqor@gmail.com** — subject: `[SECURITY] Possible tampered artifact`
2. `cosign verify` ka poora output aur exact image digest ya file hash include karo
3. We will investigate and post a GitHub Security Advisory if confirmed

---

## Security Considerations for Kerno

Kerno runs with elevated privileges (root or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_PTRACE`) to load eBPF programs into the kernel. This means:

- **eBPF programs are read-only observers.** They attach to tracepoints and kprobes to collect telemetry. They do not modify kernel state.
- **BPF verifier protection.** All eBPF programs pass the kernel's BPF verifier before loading, which guarantees they cannot crash the kernel.
- **No sensitive data logging.** Kerno does not log file contents, environment variables, authentication tokens, or network payloads.
- **Bounded resource usage.** BPF map sizes are capped to prevent kernel memory exhaustion.
- **Minimal capabilities.** We document the exact Linux capabilities required and support running without full root where possible.

## Disclosure Policy

- We follow [coordinated vulnerability disclosure](https://vuls.cert.org/confluence/display/Wiki/Vulnerability+Disclosure+Policy).
- We will credit reporters in security advisories (unless anonymity is requested).
- We use GitHub Security Advisories for publishing fixes.

## Contact

- **Security reports:** team.optiqor@gmail.com
- **General questions:** GitHub Discussions
- **Maintainer:** Shivam Kumar (@btwshivam)