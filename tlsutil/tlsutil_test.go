package tlsutil

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
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSelfSignedCert tests that SelfSignedCert generates a valid certificate.
func TestSelfSignedCert(t *testing.T) {
	cert, err := SelfSignedCert()
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected certificate bytes")
	}

	// Parse the leaf certificate to check SANs.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// Check DNS SANs include localhost and *.localhost.
	hasLocalhost, hasWildcard := false, false
	for _, name := range leaf.DNSNames {
		if name == "localhost" {
			hasLocalhost = true
		}
		if name == "*.localhost" {
			hasWildcard = true
		}
	}
	if !hasLocalhost {
		t.Error("expected 'localhost' in DNS SANs")
	}
	if !hasWildcard {
		t.Error("expected '*.localhost' in DNS SANs")
	}

	// Check IP SANs.
	has127 := false
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			has127 = true
		}
	}
	if !has127 {
		t.Error("expected 127.0.0.1 in IP SANs")
	}
}

// TestCertPoolFromPEM tests CertPoolFromPEM with valid and empty PEM.
func TestCertPoolFromPEM(t *testing.T) {
	cert, err := SelfSignedCert()
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})

	pool, err := CertPoolFromPEM(caPEM)
	if err != nil {
		t.Fatalf("CertPoolFromPEM valid: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}

	_, err = CertPoolFromPEM([]byte("not a cert"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// TestFromPEM_Errors tests the input-validation paths of FromPEM.
func TestFromPEM_Errors(t *testing.T) {
	// Empty → nil, nil.
	cfg, err := FromPEM("", "", "")
	if err != nil || cfg != nil {
		t.Errorf("empty FromPEM: cfg=%v err=%v", cfg, err)
	}

	// Cert without key → error.
	_, err = FromPEM("cert-pem", "", "")
	if err == nil {
		t.Error("expected error for cert without key")
	}

	// Key without cert → error.
	_, err = FromPEM("", "key-pem", "")
	if err == nil {
		t.Error("expected error for key without cert")
	}

	// Invalid CA PEM → error.
	_, err = FromPEM("", "", "not-a-cert")
	if err == nil {
		t.Error("expected error for invalid CA PEM in FromPEM")
	}
}

// TestFromPEM_WithCertAndKey covers the happy path: valid cert+key PEM both
// set, parsed by tls.X509KeyPair, populated into cfg.Certificates.
func TestFromPEM_WithCertAndKey(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := FromPEM(string(certPEM), string(keyPEM), "")
	if err != nil {
		t.Fatalf("FromPEM: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
}

// TestFromPEM_WithCA tests FromPEM with only a CA PEM set.
func TestFromPEM_WithCA(t *testing.T) {
	cert, err := SelfSignedCert()
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))

	cfg, err := FromPEM("", "", caPEM)
	if err != nil {
		t.Fatalf("FromPEM CA only: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

// TestFromFiles_AllEmpty tests FromFiles returns nil when all args are empty.
func TestFromFiles_AllEmpty(t *testing.T) {
	cfg, err := FromFiles("", "", "")
	if err != nil {
		t.Errorf("FromFiles empty: %v", err)
	}
	if cfg != nil {
		t.Errorf("FromFiles empty: expected nil cfg, got %+v", cfg)
	}
}

// TestFromFiles_CertWithoutKey tests that cert without key returns error.
func TestFromFiles_CertWithoutKey(t *testing.T) {
	_, err := FromFiles("some-cert.pem", "", "")
	if err == nil {
		t.Error("expected error for cert without key in FromFiles")
	}
}

// TestCertLoader_GetCertificate tests the CertLoader with a missing file.
func TestCertLoader_GetCertificate(t *testing.T) {
	loader := NewCertLoader("/nonexistent/cert.pem", "/nonexistent/key.pem")
	_, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err == nil {
		t.Error("expected error for nonexistent cert files")
	}
}

// writeCertKeyFiles generates an ECDSA P-256 self-signed cert and writes PEM
// cert + key to temp files, returning their paths.
func writeCertKeyFiles(t *testing.T) (certFile, keyFile string, caPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return certFile, keyFile, certPEM
}

func TestFromFiles_WithCertAndKey(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)

	cfg, err := FromFiles(certFile, keyFile, "")
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
}

func TestFromFiles_WithCAFile(t *testing.T) {
	_, _, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := FromFiles("", "", caFile)
	if err != nil {
		t.Fatalf("FromFiles CA only: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestFromFiles_WithCertKeyAndCA(t *testing.T) {
	certFile, keyFile, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := FromFiles(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("FromFiles cert+key+CA: %v", err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 || cfg.RootCAs == nil {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestFromFiles_NonexistentCAFile(t *testing.T) {
	_, err := FromFiles("", "", "/nonexistent/ca.pem")
	if err == nil {
		t.Error("expected error for nonexistent CA file")
	}
}

func TestFromFiles_KeyWithoutCert(t *testing.T) {
	_, err := FromFiles("", "some-key.pem", "")
	if err == nil {
		t.Error("expected error for key without cert")
	}
}

func TestCertLoader_WithRealFiles(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)

	loader := NewCertLoader(certFile, keyFile)
	cert, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected non-nil certificate")
	}
}

func TestCertLoader_CachedCert(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)

	loader := NewCertLoader(certFile, keyFile)
	first, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("first GetCertificate: %v", err)
	}
	second, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("second GetCertificate: %v", err)
	}
	if first != second {
		t.Error("expected same cached certificate pointer on second call")
	}
}

// TestCertLoader_StaleFallback covers the rotation-in-progress branch: load a
// valid cert first, then corrupt the key file and bump the cert's mtime so the
// loader re-reads. The second call must return the previously cached cert
// rather than failing the handshake.
func TestCertLoader_StaleFallback(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)
	loader := NewCertLoader(certFile, keyFile)

	cached, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("first GetCertificate: %v", err)
	}

	// Corrupt the key, then advance the cert mtime to force a reload attempt.
	if err := os.WriteFile(keyFile, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatal(err)
	}

	stale, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("expected cached cert fallback, got error: %v", err)
	}
	if stale != cached {
		t.Error("expected previously cached cert to be returned on reload failure")
	}
}

// TestCertLoader_ReloadOnMtimeChange covers the happy reload path: write a new
// cert+key pair on top of the same paths and verify the loader picks them up
// (different cert pointer, both calls succeed).
func TestCertLoader_ReloadOnMtimeChange(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)
	loader := NewCertLoader(certFile, keyFile)

	first, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("first GetCertificate: %v", err)
	}

	// Generate a fresh cert+key and overwrite the paths in place. Bump mtime
	// explicitly so the test is robust against same-second writes on coarse
	// filesystems (e.g. ext4 with second-granularity mtime).
	newCertFile, newKeyFile, _ := writeCertKeyFiles(t)
	newCertPEM, _ := os.ReadFile(newCertFile)
	newKeyPEM, _ := os.ReadFile(newKeyFile)
	if err := os.WriteFile(certFile, newCertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, newKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatal(err)
	}

	second, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("reload GetCertificate: %v", err)
	}
	if first == second {
		t.Error("expected fresh cert pointer after mtime bump, got cached one")
	}
}

// TestFromFiles_BadCertContent covers the tls.LoadX509KeyPair error path —
// paths exist but contain non-PEM garbage.
func TestFromFiles_BadCertContent(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, []byte("not a cert"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := FromFiles(certFile, keyFile, ""); err == nil {
		t.Error("expected error loading garbage cert/key, got nil")
	}
}

// TestFromPEM_BadCertContent covers tls.X509KeyPair's parse-error branch.
func TestFromPEM_BadCertContent(t *testing.T) {
	if _, err := FromPEM("not a cert", "not a key", ""); err == nil {
		t.Error("expected error parsing garbage cert/key PEM, got nil")
	}
}
