// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

func NewHTTPClient(
	timeout time.Duration,
	proxy string,
	caCertFile string,
	insecureSkipVerify bool,
) *http.Client {
	//nolint:gosec // InsecureSkipVerify is intentionally configurable for local/dev and air-gapped environments.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
	}

	if caCertFile != "" {
		certPool, err := x509.SystemCertPool()
		if err != nil || certPool == nil {
			certPool = x509.NewCertPool()
		}
		//nolint:gosec // CA certificate path is intentionally user-configurable via trusted config.
		caCert, err := os.ReadFile(caCertFile)
		if err == nil {
			ok := certPool.AppendCertsFromPEM(caCert)
			if ok {
				tlsConfig.RootCAs = certPool
			}
		}
	}

	transport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func formatHTTPError(err error) error {
	if err == nil {
		return nil
	}

	var unknownAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthErr) {
		return fmt.Errorf(
			"TLS verification failed for certificate subject %q: %w. "+
				"If your environment uses a corporate MITM proxy, configure ai.ca_cert_file",
			unknownAuthErr.Cert.Subject,
			err,
		)
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return fmt.Errorf(
			"TLS hostname verification failed for host %q: %w",
			hostnameErr.Host,
			err,
		)
	}

	return fmt.Errorf(
		"HTTP request failed: %w. "+
			"If using a corporate proxy or custom CA, configure ai.ca_cert_file or ai.proxy",
		err,
	)
}
