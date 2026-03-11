# Security Policy

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Kerno, please report it responsibly:

1. **Email:** Send a detailed report to **security@lowplane.dev**
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

- **Security reports:** security@lowplane.dev
- **General questions:** GitHub Discussions
- **Maintainer:** Shivam Kumar (@btwshivam)
