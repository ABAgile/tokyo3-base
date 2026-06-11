package jetstream

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAuditTLS verifies which TLS construction each material combination
// gets. The full cert+key pair must produce a per-handshake reloading
// config (GetClientCertificate callback, no boot-pinned Certificates) —
// that's the contract that lets a cert-agentd rotation land on the next
// reconnect. Anything short of a pair must keep FromFiles' semantics so
// the CA-only and plaintext dev paths are unchanged.
func TestAuditTLS(t *testing.T) {
	certFile, keyFile, caFile := writeAuditCertFiles(t)

	t.Run("pair reloads leaf and CA per handshake", func(t *testing.T) {
		cfg, err := auditTLS(certFile, keyFile, caFile)
		if err != nil {
			t.Fatalf("auditTLS: %v", err)
		}
		if cfg.GetClientCertificate == nil {
			t.Error("GetClientCertificate is nil — leaf would be pinned at boot")
		}
		if len(cfg.Certificates) != 0 {
			t.Errorf("Certificates = %d entries, want none (static leaf defeats reload)", len(cfg.Certificates))
		}
		if cfg.RootCAs != nil {
			t.Error("RootCAs set — a frozen pool defeats CA hot-reload")
		}
		if cfg.VerifyConnection == nil || !cfg.InsecureSkipVerify {
			t.Error("VerifyConnection + InsecureSkipVerify not wired for live-pool verification")
		}
	})

	t.Run("ca-only keeps one-shot server-auth TLS", func(t *testing.T) {
		cfg, err := auditTLS("", "", caFile)
		if err != nil {
			t.Fatalf("auditTLS: %v", err)
		}
		if cfg.GetClientCertificate != nil {
			t.Error("GetClientCertificate set without a client pair")
		}
		if cfg.RootCAs == nil {
			t.Error("RootCAs is nil — CAFile was provided")
		}
	})

	t.Run("no material stays plaintext", func(t *testing.T) {
		cfg, err := auditTLS("", "", "")
		if err != nil {
			t.Fatalf("auditTLS: %v", err)
		}
		if cfg != nil {
			t.Errorf("cfg = %+v, want nil (plaintext)", cfg)
		}
	})

	t.Run("missing pair files fail closed", func(t *testing.T) {
		if _, err := auditTLS("/no/such/cert.pem", "/no/such/key.pem", ""); err == nil {
			t.Error("expected error for missing cert+key files")
		}
	})
}

// TestNewAuditSink_MTLS_UnreachableURL: the mTLS path must inherit the
// lazy-connect property — valid material plus an unreachable broker is
// a queued sink, not a startup failure — and announce mTLS in the boot
// log so operators can confirm the channel is authenticated.
func TestNewAuditSink_MTLS_UnreachableURL_NoStartupError(t *testing.T) {
	certFile, keyFile, caFile := writeAuditCertFiles(t)
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sink, err := NewAuditSink[struct{}](AuditSinkConfig{
		URL:       "nats://127.0.0.1:1",
		CertFile:  certFile,
		KeyFile:   keyFile,
		CAFile:    caFile,
		Subject:   "test.audit.events",
		EnvPrefix: "TEST_NATS",
		Log:       log,
	})
	if err != nil {
		t.Fatalf("NewAuditSink (mTLS, unreachable broker): %v", err)
	}
	if sink == nil {
		t.Fatal("sink is nil")
	}
	if !strings.Contains(buf.String(), "with mTLS") {
		t.Errorf("missing mTLS info log:\n%s", buf.String())
	}
}

// writeAuditCertFiles writes a self-signed client cert, its key, and a
// CA bundle (the cert itself) into a temp dir. Mirrors applog's
// writeMTLSCertFiles; duplicated because test helpers don't cross
// package boundaries.
func writeAuditCertFiles(t *testing.T) (certFile, keyFile, caFile string) {
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
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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
	caFile = filepath.Join(dir, "ca.pem")
	for path, data := range map[string][]byte{certFile: certPEM, keyFile: keyPEM, caFile: certPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return certFile, keyFile, caFile
}
