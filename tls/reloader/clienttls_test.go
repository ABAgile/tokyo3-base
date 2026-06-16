package reloader_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/abagile/tokyo3-base/tls/reloader"
)

func caFileFrom(t *testing.T, caPEM []byte) string {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile
}

func TestClientTLS_PairUsesHotReload(t *testing.T) {
	certFile, keyFile, caPEM := writeCertKeyFiles(t)
	cfg, err := reloader.ClientTLS(certFile, keyFile, caFileFrom(t, caPEM))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GetClientCertificate == nil {
		t.Error("a cert+key pair should yield a hot-reloading GetClientCertificate (ClientConfig path)")
	}
	if !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil {
		t.Error("pair+CA should verify via VerifyConnection against the live pool")
	}
}

func TestClientTLS_CAOnlyVerifies(t *testing.T) {
	_, _, caPEM := writeCertKeyFiles(t)
	cfg, err := reloader.ClientTLS("", "", caFileFrom(t, caPEM))
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("CA-only should return a verifying config, not nil")
	}
	if cfg.RootCAs == nil {
		t.Error("CA-only should populate RootCAs (fail-secure: honor the provided CA)")
	}
	if cfg.GetClientCertificate != nil {
		t.Error("CA-only should present no client cert")
	}
	if cfg.InsecureSkipVerify {
		t.Error("CA-only must NOT skip verification")
	}
}

func TestClientTLS_NothingIsPlaintext(t *testing.T) {
	cfg, err := reloader.ClientTLS("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Errorf("no material should return (nil, nil) so the DSN/plaintext governs, got %+v", cfg)
	}
}
