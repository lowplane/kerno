// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestHTTPClient_TLSVerificationFails(t *testing.T) {
	server := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
	)
	defer server.Close()

	client := NewHTTPClient(
		5*time.Second,
		"",
		"",
		false,
	)

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		server.URL,
		nil,
	)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected TLS verification error, got nil")
	}
}

func TestHTTPClient_InsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
	)
	defer server.Close()

	client := NewHTTPClient(
		5*time.Second,
		"",
		"",
		true,
	)
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		server.URL,
		nil,
	)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected successful request, got error : %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestHTTPClient_CustomCA(t *testing.T) {
	server := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
	)
	defer server.Close()

	// Export server cert as PEM
	cert := server.Certificate()

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	tmpFile, err := os.CreateTemp("", "kerno-ca-*.crt")
	if err != nil {
		t.Fatalf("creating temp cert file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(pemData); err != nil {
		t.Fatalf("writing cert file: %v", err)
	}

	if err := tmpFile.Close(); err != nil {
		t.Fatalf("closing cert file: %v", err)
	}

	client := NewHTTPClient(
		5*time.Second,
		"",
		tmpFile.Name(),
		false,
	)

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		server.URL,
		nil,
	)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected successful request with custom CA, got : %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestHTTPClient_CustomProxy(t *testing.T) {
	client := NewHTTPClient(
		5*time.Second,
		"http://localhost:8080",
		"",
		false,
	)

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	req := &http.Request{
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
		},
	}

	proxyURL, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("proxy function returned error: %v", err)
	}

	if proxyURL == nil {
		t.Fatal("expected proxy URL, got nil")
	}

	if proxyURL.String() != "http://localhost:8080" {
		t.Fatalf("unexpected proxy URL: %s", proxyURL.String())
	}
}
