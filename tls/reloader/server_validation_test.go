package reloader_test

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/tls/reloader"
)

func TestServerTLS_RejectsMissingAndMalformedCerts(t *testing.T) {
	cert, key, _ := writeCertKeyFiles(t)
	if _, err := reloader.ServerTLS(reloader.ServerTLSConfig{CertFile: "/no/such/cert", KeyFile: key, Log: discard()}); err == nil {
		t.Fatal("missing certificate accepted")
	}
	if err := os.WriteFile(cert, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reloader.ServerTLS(reloader.ServerTLSConfig{CertFile: cert, KeyFile: key, Log: discard()}); err == nil {
		t.Fatal("malformed certificate accepted")
	}
}

func TestServerTLS_LogsFailedReloadAndKeepsCertificate(t *testing.T) {
	cert, key, _ := writeCertKeyFiles(t)
	var logs bytes.Buffer
	cfg, err := reloader.ServerTLS(reloader.ServerTLSConfig{CertFile: cert, KeyFile: key, Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	previous, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, []byte("broken rotation"), 0600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(cert, future, future); err != nil {
		t.Fatal(err)
	}
	current, err := cfg.GetCertificate(nil)
	if err != nil || current != previous {
		t.Fatalf("reload lost old certificate: %v", err)
	}
	if !strings.Contains(logs.String(), "kept previous cert") {
		t.Fatalf("reload failure was silent: %s", logs.String())
	}
}
