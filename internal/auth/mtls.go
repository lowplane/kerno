// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSConfig builds a *tls.Config for the metrics HTTP server.
//
//   - certFile + keyFile → one-way TLS (server authenticates to client).
//   - certFile + keyFile + caFile → mutual TLS: the server additionally
//     requires the client to present a certificate signed by caFile's CA.
//
// Returns nil when certFile is empty, indicating that plain HTTP should be
// used (i.e. auth.mode is "none" or "bearer" without TLS).
func TLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" {
		return nil, nil
	}
	if keyFile == "" {
		return nil, fmt.Errorf("auth: tls key_file must be set when cert_file is configured")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("auth: loading server TLS keypair: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Enforce TLS 1.3 minimum — TLS 1.2 has known downgrade vectors
		// that matter for a metrics endpoint exposed inside a cluster.
		MinVersion: tls.VersionTLS13,
	}

	if caFile != "" {
		pool, err := loadCertPool(caFile)
		if err != nil {
			return nil, fmt.Errorf("auth: loading client CA bundle: %w", err)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}

// loadCertPool reads a PEM-encoded CA certificate bundle and returns a cert
// pool suitable for use as tls.Config.ClientCAs.
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid PEM certificates found in %q", path)
	}
	return pool, nil
}
