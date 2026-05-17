// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/auth"
)

// generateCertificates generates a CA, a server cert, and a client cert.
// It writes them to the temp dir and returns the file paths.
func generateCertificates(t *testing.T) (caPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath string) {
	t.Helper()
	dir := t.TempDir()

	// 1. Generate CA
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Optiqor Test CA"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	caPath = filepath.Join(dir, "ca.crt")
	writePEM(t, caPath, "CERTIFICATE", caBytes)

	// 2. Generate Server Cert
	serverPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Optiqor Server"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	serverBytes, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}

	serverCertPath = filepath.Join(dir, "server.crt")
	serverKeyPath = filepath.Join(dir, "server.key")
	writePEM(t, serverCertPath, "CERTIFICATE", serverBytes)
	writeKey(t, serverKeyPath, serverPriv)

	// 3. Generate Client Cert
	clientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{Organization: []string{"Optiqor Client"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	clientBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed to create client cert: %v", err)
	}

	clientCertPath = filepath.Join(dir, "client.crt")
	clientKeyPath = filepath.Join(dir, "client.key")
	writePEM(t, clientCertPath, "CERTIFICATE", clientBytes)
	writeKey(t, clientKeyPath, clientPriv)

	return
}

func writePEM(t *testing.T, path, blockType string, bytes []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: bytes}); err != nil {
		t.Fatalf("failed to encode %s: %v", blockType, err)
	}
}

func writeKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	writePEM(t, path, "EC PRIVATE KEY", b)
}

func TestTLSConfig_Empty(t *testing.T) {
	cfg, err := auth.TLSConfig("", "", "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config, got %v", cfg)
	}
}

func TestTLSConfig_MissingKey(t *testing.T) {
	_, err := auth.TLSConfig("server.crt", "", "")
	if err == nil {
		t.Fatal("expected error when key is missing, got nil")
	}
}

func TestTLSConfig_OneWay(t *testing.T) {
	_, serverCert, serverKey, _, _ := generateCertificates(t)

	cfg, err := auth.TLSConfig(serverCert, serverKey, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected NoClientCert, got %v", cfg.ClientAuth)
	}
}

func TestTLSConfig_MutualTLS(t *testing.T) {
	caPath, serverCert, serverKey, _, _ := generateCertificates(t)

	cfg, err := auth.TLSConfig(serverCert, serverKey, caPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected RequireAndVerifyClientCert, got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("expected ClientCAs to be set")
	}
}

func TestTLSConfig_InvalidCA(t *testing.T) {
	_, serverCert, serverKey, _, _ := generateCertificates(t)

	// Create an invalid CA file
	badCA := filepath.Join(t.TempDir(), "bad_ca.crt")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("writing bad CA: %v", err)
	}

	_, err := auth.TLSConfig(serverCert, serverKey, badCA)
	if err == nil {
		t.Fatal("expected error with bad CA, got nil")
	}
}

func TestMTLSEndToEnd(t *testing.T) {
	caPath, serverCert, serverKey, clientCert, clientKey := generateCertificates(t)

	// Build the server TLS config using our function
	tlsCfg, err := auth.TLSConfig(serverCert, serverKey, caPath)
	if err != nil {
		t.Fatalf("TLSConfig failed: %v", err)
	}

	// Create a test server
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secure data"))
	}))
	ts.TLS = tlsCfg
	ts.StartTLS()
	defer ts.Close()

	// 1. Try with no client cert (should fail)
	noCertClient := ts.Client() // uses standard transport that trusts the server cert, but no client cert
	req1, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp1, err := noCertClient.Do(req1)
	if err == nil {
		resp1.Body.Close()
		t.Fatal("expected request without client cert to fail")
	}

	// 2. Try with valid client cert (should succeed)
	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatalf("failed to load client keypair: %v", err)
	}
	
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("failed to read ca cert: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	validClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp2, err := validClient.Do(req2)
	if err != nil {
		t.Fatalf("expected request with valid client cert to succeed, got error: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp2.StatusCode)
	}
}
