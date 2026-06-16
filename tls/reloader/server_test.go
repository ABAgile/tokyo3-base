package reloader_test

import (
	"crypto/tls"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/abagile/tokyo3-base/tls/reloader"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestServerTLS_SelfSignedFallback(t *testing.T) {
	cfg, err := reloader.ServerTLS(reloader.ServerTLSConfig{Log: discard()})
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("want 1 self-signed cert, got %d", len(cfg.Certificates))
	}
	if cfg.GetCertificate != nil {
		t.Error("self-signed path should not set GetCertificate")
	}
}

func TestServerTLS_MismatchedPairIsError(t *testing.T) {
	if _, err := reloader.ServerTLS(reloader.ServerTLSConfig{CertFile: "x.pem", Log: discard()}); err == nil {
		t.Fatal("want error when only CertFile is set")
	}
	if _, err := reloader.ServerTLS(reloader.ServerTLSConfig{KeyFile: "x.key", Log: discard()}); err == nil {
		t.Fatal("want error when only KeyFile is set")
	}
}

func TestServerTLS_CertFilesEnableHotReload(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)

	cfg, err := reloader.ServerTLS(reloader.ServerTLSConfig{CertFile: certFile, KeyFile: keyFile, MinVersion: tls.VersionTLS13, Log: discard()})
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	if cfg.GetCertificate == nil {
		t.Error("cert-file path should set GetCertificate for hot reload")
	}
	if len(cfg.Certificates) != 0 {
		t.Error("cert-file path should not set static Certificates")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want %x", cfg.MinVersion, tls.VersionTLS13)
	}
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{}); err != nil {
		t.Errorf("GetCertificate failed: %v", err)
	}
}

func TestServerTLS_ClientCAEnablesMTLS(t *testing.T) {
	certFile, keyFile, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := reloader.ServerTLS(reloader.ServerTLSConfig{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile, Log: discard()})
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven (zero-value default)", cfg.ClientAuth)
	}
	if cfg.GetConfigForClient == nil && cfg.ClientCAs == nil {
		t.Error("client CA path should wire ClientCAs / GetConfigForClient")
	}
}
