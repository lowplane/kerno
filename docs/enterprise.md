# Enterprise Deployments

This page describes how to run Kerno's AI features in regulated or corporate
environments where outbound HTTPS passes through an authenticating proxy and/or
a MITM device that re-signs traffic with a private root CA.

---

## Why this matters

Kerno's AI features (`kerno doctor --ai`, `kerno explain`) call external APIs
(Anthropic, OpenAI) or an internal Ollama instance over HTTPS.  In a typical
Fortune 500 / regulated deployment every outbound HTTPS connection is routed
through a corporate proxy that:

1. Intercepts the TLS handshake.
2. Re-signs the server certificate with an internal root CA.
3. Forwards the (decrypted) request.

The OS trust store knows about that internal CA, so `curl`, browsers, and most
other tools work fine.  Go binaries that don't explicitly load extra CAs **do
not** inherit the OS store on all platforms – they get a
`certificate signed by unknown authority` error and silently fail.

Kerno's AI HTTP client is built to handle this correctly.

---

## Configuration

All settings live under the `ai:` key in `config.yaml` (or as `KERNO_*` env
vars).

```yaml
ai:
  enabled: true
  provider: anthropic   # anthropic | openai | ollama

  # ── Proxy ────────────────────────────────────────────────────────────────
  # Optional.  When set, ALL AI provider traffic goes through this proxy.
  # If blank, the standard HTTPS_PROXY / HTTP_PROXY / NO_PROXY environment
  # variables are honoured automatically (Go default behaviour).
  proxy: http://corp-proxy.internal:8080

  # ── Corporate CA ─────────────────────────────────────────────────────────
  # Path to a PEM-encoded CA certificate or bundle that will be APPENDED to
  # the system root CA pool.  Your system roots are never replaced.
  # Typical paths:
  #   Linux:  /etc/kerno/corp-ca.crt  or  /etc/ssl/certs/corp-ca.crt
  #   macOS:  /Library/Keychains/System.keychain  (export first)
  ca_cert_file: /etc/kerno/corp-ca.crt

  # ── TLS ──────────────────────────────────────────────────────────────────
  # NEVER set this to true in production.  For local dev only.
  insecure_skip_verify: false

  # ── Timeout ──────────────────────────────────────────────────────────────
  timeout: 30s
```

### Environment-variable equivalents

| Config field              | Env var                          |
|---------------------------|----------------------------------|
| `ai.proxy`                | `KERNO_AI_PROXY`                 |
| `ai.ca_cert_file`         | `KERNO_AI_CA_CERT_FILE`          |
| `ai.insecure_skip_verify` | `KERNO_AI_INSECURE_SKIP_VERIFY`  |
| `ai.timeout`              | `KERNO_AI_TIMEOUT`               |

Precedence: CLI flags > env vars > config file > defaults.

---

## Scenarios

### Scenario 1 – HTTPS_PROXY only (no custom CA)

Your proxy is trusted by the OS already (e.g. it forwards without MITM):

```bash
export HTTPS_PROXY=http://corp-proxy.internal:8080
kerno doctor --ai
```

No config change needed.  Go's default transport reads `HTTPS_PROXY`
automatically.

---

### Scenario 2 – MITM proxy with a corporate root CA

The proxy re-signs traffic.  You need to give Kerno the CA:

```bash
# Export the corporate root CA (ask your IT team):
# e.g. on Linux it's often at /usr/local/share/ca-certificates/corp.crt

# Option A – config file
cat > /etc/kerno/config.yaml <<'EOF'
ai:
  proxy: http://corp-proxy.internal:8080
  ca_cert_file: /etc/kerno/corp-ca.crt
EOF

kerno doctor --ai

# Option B – env vars only (no file)
KERNO_AI_PROXY=http://corp-proxy.internal:8080 \
KERNO_AI_CA_CERT_FILE=/etc/kerno/corp-ca.crt \
kerno doctor --ai
```

---

### Scenario 3 – Air-gapped with Ollama

No internet access; Ollama runs inside the cluster behind a TLS-terminating
reverse proxy signed by your internal CA:

```yaml
ai:
  enabled: true
  provider: ollama
  model: llama3
  ca_cert_file: /etc/kerno/corp-ca.crt
  # no proxy needed – Ollama is reachable directly
```

---

### Scenario 4 – Kubernetes DaemonSet

Mount the corporate CA as a Secret and reference it in your Helm values:

```yaml
# values.yaml
extraVolumes:
  - name: corp-ca
    secret:
      secretName: corp-ca-bundle

extraVolumeMounts:
  - name: corp-ca
    mountPath: /etc/kerno/certs
    readOnly: true

env:
  - name: KERNO_AI_CA_CERT_FILE
    value: /etc/kerno/certs/corp-ca.crt
  - name: KERNO_AI_PROXY
    value: http://corp-proxy.internal:8080
  - name: KERNO_AI_API_KEY
    valueFrom:
      secretKeyRef:
        name: kerno-ai
        key: api_key
```

---

## Verifying proxy routing

Run `mitmproxy` in a sidecar or on the proxy host, then:

```bash
HTTPS_PROXY=http://localhost:8080 kerno doctor --ai
```

You should see the request to `api.anthropic.com` appear in the mitmproxy UI.

---

## Reading TLS errors

When TLS verification fails, Kerno prints an actionable message:

```
kerno/ai: TLS certificate verification failed for api.anthropic.com

  Certificate subject : CN=api.anthropic.com,O=Anthropic
  Issuer              : CN=CorpProxy CA,O=Acme Corp
  Valid until         : 2026-01-01T00:00:00Z

  This usually means traffic is being inspected by a corporate MITM proxy
  whose root CA is not trusted by this binary.

  To fix:
    1. Set  config.ai.ca_cert_file  to the path of your corporate CA bundle
       (e.g.  ca_cert_file: /etc/kerno/corp-ca.crt)
    2. OR export HTTPS_PROXY to route via a proxy that your OS trusts.
    3. See docs: https://github.com/optiqor/kerno/blob/main/docs/enterprise.md
```

The cert subject and issuer tell you which CA signed the intercepted
certificate.  Give that CA's PEM file to `ca_cert_file`.

---

## Obtaining your corporate CA certificate

```bash
# Linux (if your IT team has installed it in the OS trust store)
ls /usr/local/share/ca-certificates/   # Debian/Ubuntu
ls /etc/pki/ca-trust/source/anchors/   # RHEL/Fedora

# Extract from the proxy itself using openssl
openssl s_client -connect api.anthropic.com:443 \
  -proxy corp-proxy.internal:8080 \
  -showcerts </dev/null 2>/dev/null \
  | awk '/BEGIN CERT/,/END CERT/' > /tmp/chain.pem
# The last cert in chain.pem is usually the root CA.
```
