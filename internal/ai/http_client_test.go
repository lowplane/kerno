package ai

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
	"strings"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/config"
)

// ---------------------------------------------------------------------------
// Helpers – generate a self-signed CA and an issued leaf certificate
// ---------------------------------------------------------------------------

type testCA struct {
	certDER []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Kerno Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &testCA{certDER: der, cert: cert, key: key}
}

func (ca *testCA) pemBytes() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certDER})
}

func (ca *testCA) issueTLSCert(t *testing.T, dnsName string, ipAddrs []net.IP) tls.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		IPAddresses:  ipAddrs,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load leaf TLS cert: %v", err)
	}
	return tlsCert
}

// writeTempPEM writes PEM bytes to a temp file and returns its path.
func writeTempPEM(t *testing.T, pemBytes []byte) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(f, pemBytes, 0o600); err != nil {
		t.Fatalf("write temp CA file: %v", err)
	}
	return f
}

// newTLSServerWithCA starts an httptest.Server using a certificate issued by
// the given CA.  The cert carries an IP SAN for 127.0.0.1 so that clients
// connecting to the loopback address pass hostname verification.
func newTLSServerWithCA(t *testing.T, ca *testCA) *httptest.Server {
	t.Helper()
	leafCert := ca.issueTLSCert(t, "localhost", []net.IP{net.ParseIP("127.0.0.1")})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leafCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestNewHTTPClient_CustomCA verifies that a client built with ca_cert_file
// pointing at our test CA can reach the TLS server it signed.
func TestNewHTTPClient_CustomCA(t *testing.T) {
	ca := newTestCA(t)
	srv := newTLSServerWithCA(t, ca)
	caFile := writeTempPEM(t, ca.pemBytes())

	cfg := &config.Config{}
	cfg.AI.CACertFile = caFile
	cfg.AI.Timeout = 5 * time.Second

	client, err := NewHTTPClient(cfg)
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET %s: %v", srv.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestNewHTTPClient_WrongCA verifies that using the wrong CA produces an
// actionable error message that mentions the ca_cert_file config key.
func TestNewHTTPClient_WrongCA(t *testing.T) {
	serverCA := newTestCA(t)
	wrongCA := newTestCA(t)

	srv := newTLSServerWithCA(t, serverCA)

	// Build a client that trusts the wrong CA.
	wrongCAFile := writeTempPEM(t, wrongCA.pemBytes())
	cfg := &config.Config{}
	cfg.AI.CACertFile = wrongCAFile
	cfg.AI.Timeout = 5 * time.Second

	client, err := NewHTTPClient(cfg)
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	_, err = client.Get(srv.URL)
	if err == nil {
		t.Fatal("expected TLS error, got nil")
	}

	errMsg := err.Error()

	// The pretty error must include the ca_cert_file hint.
	if !strings.Contains(errMsg, "ca_cert_file") {
		t.Errorf("error message does not mention ca_cert_file:\n%s", errMsg)
	}

	// It must reference the enterprise docs.
	if !strings.Contains(errMsg, "enterprise.md") {
		t.Errorf("error message does not reference enterprise docs:\n%s", errMsg)
	}

	// It must not be a bare x509 error – it should be wrapped.
	if !strings.Contains(errMsg, "TLS certificate verification failed") {
		t.Errorf("error message missing expected prefix:\n%s", errMsg)
	}
}

// TestNewHTTPClient_DefaultCase verifies that a zero-config client can be
// created without error (no proxy, no extra CA, no timeout).  We don't make
// a real network request here – just check that construction succeeds and
// uses ProxyFromEnvironment.
func TestNewHTTPClient_DefaultCase(t *testing.T) {
	cfg := &config.Config{}

	client, err := NewHTTPClient(cfg)
	if err != nil {
		t.Fatalf("NewHTTPClient with zero config: %v", err)
	}

	if client.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %s", client.Timeout)
	}
}

// TestNewHTTPClient_BadCACertFile verifies that a non-existent ca_cert_file
// returns a clear error at client-construction time (not silently).
func TestNewHTTPClient_BadCACertFile(t *testing.T) {
	cfg := &config.Config{}
	cfg.AI.CACertFile = "/this/file/does/not/exist.crt"

	_, err := NewHTTPClient(cfg)
	if err == nil {
		t.Fatal("expected error for missing ca_cert_file, got nil")
	}
	if !strings.Contains(err.Error(), "reading ca_cert_file") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestNewHTTPClient_InsecureSkipVerify verifies that setting insecure_skip_verify
// skips TLS verification (useful for dev, dangerous in prod).
func TestNewHTTPClient_InsecureSkipVerify(t *testing.T) {
	// Use a server signed by a CA we don't trust.
	unknownCA := newTestCA(t)
	srv := newTLSServerWithCA(t, unknownCA)

	cfg := &config.Config{}
	cfg.AI.InsecureSkipVerify = true
	cfg.AI.Timeout = 5 * time.Second

	client, err := NewHTTPClient(cfg)
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET with insecure_skip_verify=true failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestBuildProxyFunc_Explicit verifies that an explicit proxy URL in config
// is returned for every request.
func TestBuildProxyFunc_Explicit(t *testing.T) {
	fn := buildProxyFunc("http://corp-proxy.internal:8080")
	req, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com", nil)
	u, err := fn(req)
	if err != nil {
		t.Fatalf("proxy func error: %v", err)
	}
	if u == nil || u.Host != "corp-proxy.internal:8080" {
		t.Errorf("unexpected proxy URL: %v", u)
	}
}

// TestBuildProxyFunc_Empty verifies that an empty proxy config returns
// http.ProxyFromEnvironment (the function pointer won't be equal, but at
// least it should not return an error for a simple request when no env var
// is set).
func TestBuildProxyFunc_Empty(t *testing.T) {
	fn := buildProxyFunc("")
	req, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com", nil)
	_, err := fn(req)
	if err != nil {
		t.Errorf("proxy func error with empty config: %v", err)
	}
}
