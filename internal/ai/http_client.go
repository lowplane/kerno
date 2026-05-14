// Package ai provides AI provider integrations for Kerno.
// This file builds a shared *http.Client that honours:
//
//   - HTTPS_PROXY / HTTP_PROXY / NO_PROXY env vars (Go default transport already does this)
//   - An explicit per-provider proxy URL from config (overrides env)
//   - Extra CA certificates loaded from the system pool + a configurable file
//   - A pretty, actionable error message on TLS verification failure
//
// Nothing in this file changes the global http.DefaultTransport; callers get
// a fresh client scoped to the AI subsystem.
package ai

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/optiqor/kerno/internal/config"
)

// NewHTTPClient returns an *http.Client configured for Kerno AI providers.
//
// Behaviour, in priority order:
//  1. If cfg.AI.Proxy is set, that URL is used as the CONNECT proxy.
//     Otherwise the standard HTTPS_PROXY / HTTP_PROXY / NO_PROXY env vars
//     are honoured (Go's http.ProxyFromEnvironment, which is the default).
//  2. The system CA pool is loaded first.  If cfg.AI.CACertFile is non-empty,
//     that PEM file is appended to the pool without replacing system roots.
//  3. If cfg.AI.InsecureSkipVerify is true a warning is logged and TLS
//     verification is disabled.  This must never be set in production.
//  4. Timeout defaults to 30 s; cfg.AI.Timeout overrides it.
func NewHTTPClient(cfg *config.Config) (*http.Client, error) {
	timeout := 30 * time.Second
	if cfg.AI.Timeout > 0 {
		timeout = cfg.AI.Timeout
	}

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("ai: building TLS config: %w", err)
	}

	transport := &http.Transport{
		// Keep the defaults that make Go's transport production-ready.
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,

		TLSClientConfig: tlsCfg,

		// Proxy selection: config-level override wins, falls back to env.
		Proxy: buildProxyFunc(cfg.AI.Proxy),
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: &tlsErrorTransport{wrapped: transport},
	}, nil
}

// buildTLSConfig assembles the *tls.Config for the AI HTTP client.
func buildTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.AI.InsecureSkipVerify {
		// Loud warning – this path must never be reached in production.
		fmt.Fprintln(os.Stderr,
			"[kerno/ai] WARNING: insecure_skip_verify=true — TLS verification is DISABLED. "+
				"Do not use this in production.")
		return &tls.Config{InsecureSkipVerify: true}, nil //nolint:gosec // intentional, guarded by config
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		// SystemCertPool can fail on some minimal container images.
		// Fall back to an empty pool and rely on the extra file.
		pool = x509.NewCertPool()
	}

	if cfg.AI.CACertFile != "" {
		pem, err := os.ReadFile(cfg.AI.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("reading ca_cert_file %q: %w", cfg.AI.CACertFile, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf(
				"ca_cert_file %q contained no valid PEM certificates — "+
					"verify it is a PEM-encoded CA bundle (not DER/PKCS12)",
				cfg.AI.CACertFile,
			)
		}
	}

	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// buildProxyFunc returns an http.Transport-compatible proxy function.
//
//   - If proxyURL is empty, it falls back to http.ProxyFromEnvironment so that
//     HTTPS_PROXY / HTTP_PROXY / NO_PROXY continue to work out of the box.
//   - If proxyURL is set, that single URL is used for every request.
func buildProxyFunc(proxyURL string) func(*http.Request) (*url.URL, error) {
	if proxyURL == "" {
		return http.ProxyFromEnvironment
	}

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		// Return a function that surfaces the parse error at request time so
		// that the binary still starts up; the error will be visible on the
		// first AI call.
		return func(*http.Request) (*url.URL, error) {
			return nil, fmt.Errorf("ai: invalid proxy URL %q in config: %w", proxyURL, err)
		}
	}

	return func(*http.Request) (*url.URL, error) {
		return parsed, nil
	}
}

// ---------------------------------------------------------------------------
// Pretty TLS error transport
// ---------------------------------------------------------------------------

// tlsErrorTransport wraps an http.RoundTripper and converts opaque TLS
// certificate-verification errors into actionable, human-readable messages
// that include the certificate subject and a pointer to the enterprise-CA
// configuration documentation.
type tlsErrorTransport struct {
	wrapped http.RoundTripper
}

func (t *tlsErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.wrapped.RoundTrip(req)
	if err == nil {
		return resp, nil
	}

	if isTLSError(err) {
		return nil, buildTLSError(req, err)
	}

	return nil, err
}

// isTLSError returns true for the subset of errors that originate from TLS
// certificate verification.
func isTLSError(err error) bool {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}

	// Fallback heuristic for older Go versions / wrapped errors.
	msg := err.Error()
	return strings.Contains(msg, "certificate") &&
		(strings.Contains(msg, "signed by unknown authority") ||
			strings.Contains(msg, "certificate is not trusted") ||
			strings.Contains(msg, "x509:"))
}

// buildTLSError constructs the pretty error message.
func buildTLSError(req *http.Request, underlying error) error {
	var certErr *tls.CertificateVerificationError
	var certInfo string
	if errors.As(underlying, &certErr) && len(certErr.UnverifiedCertificates) > 0 {
		leaf := certErr.UnverifiedCertificates[0]
		certInfo = fmt.Sprintf(
			"\n  Certificate subject : %s"+
				"\n  Issuer              : %s"+
				"\n  Valid until         : %s",
			leaf.Subject.String(),
			leaf.Issuer.String(),
			leaf.NotAfter.Format(time.RFC3339),
		)
	}

	return fmt.Errorf(
		"kerno/ai: TLS certificate verification failed for %s%s\n\n"+
			"  This usually means traffic is being inspected by a corporate MITM proxy\n"+
			"  whose root CA is not trusted by this binary.\n\n"+
			"  To fix:\n"+
			"    1. Set  config.ai.ca_cert_file  to the path of your corporate CA bundle\n"+
			"       (e.g.  ca_cert_file: /etc/kerno/corp-ca.crt)\n"+
			"    2. OR export HTTPS_PROXY to route via a proxy that your OS trusts.\n"+
			"    3. See docs: https://github.com/optiqor/kerno/blob/main/docs/enterprise.md\n\n"+
			"  Underlying error: %w",
		req.URL.Host, certInfo, underlying,
	)
}
