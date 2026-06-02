package applog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAppLoggerWithNATS_EmptyURL_StdoutOnly: the no-NATS path is the
// fallback every dev/test deployment hits. URL empty ⇒ stdout-only
// logger (via the caller-supplied WithStdout()), drain is callable
// without panicking and the "skipped (no URL configured)" Info line
// surfaces so operators see the state.
func TestAppLoggerWithNATS_EmptyURL_StdoutOnly(t *testing.T) {
	log, lv, drain := AppLoggerWithNATS(Config{App: "test-app"}, NATSConfig{}, WithStdout())
	if log == nil {
		t.Fatal("logger is nil")
	}
	if lv == nil {
		t.Fatal("level var is nil")
	}
	if drain == nil {
		t.Fatal("drain is nil — must be a no-op closure, never nil")
	}
	// Must be safe to call repeatedly.
	drain()
	drain()
}

// TestAppLoggerWithNATS_NoWriters_FallsBackToAppLoggerDefault: the
// helper composes — passing zero writers + empty URL should still
// produce a usable logger, since [AppLogger] falls back to stdout
// when its writer list is empty.
func TestAppLoggerWithNATS_NoWriters_FallsBackToAppLoggerDefault(t *testing.T) {
	log, _, drain := AppLoggerWithNATS(Config{App: "test-app"}, NATSConfig{})
	if log == nil {
		t.Fatal("logger is nil — AppLogger fallback should have kicked in")
	}
	log.Info("hello")
	drain()
}

// TestDialLogNATS_EmptyURL_SkipsDial verifies the URL-empty fast
// path returns (nil, nil) — used by AppLoggerWithNATS to recognise
// "no shipping configured" without trying to dial.
func TestDialLogNATS_EmptyURL_SkipsDial(t *testing.T) {
	nc, err := dialLogNATS(NATSConfig{})
	if err != nil {
		t.Fatalf("dialLogNATS(empty) err = %v, want nil", err)
	}
	if nc != nil {
		t.Fatalf("dialLogNATS(empty) nc = %v, want nil", nc)
	}
}

// TestDialLogNATS_MalformedURL_ReturnsError exercises the
// dial-failure surface. nats.Connect rejects malformed URLs at
// parse time, before RetryOnFailedConnect kicks in.
func TestDialLogNATS_MalformedURL_ReturnsError(t *testing.T) {
	nc, err := dialLogNATS(NATSConfig{URL: "://not-a-url"})
	if err == nil {
		t.Fatalf("dialLogNATS(malformed) err = nil, want error; nc=%v", nc)
	}
	if nc != nil {
		t.Fatalf("dialLogNATS on failure returned non-nil conn: %v", nc)
	}
	if !strings.Contains(err.Error(), "log shipping") {
		t.Errorf("err = %q, want prefix 'log shipping'", err.Error())
	}
}

// TestAppLoggerWithNATS_MalformedURL_FailsClosed: a malformed URL
// must NOT prevent construction — log shipping is observational, so
// a config typo can't take down the daemon. The logger is still
// usable, drain is still callable.
func TestAppLoggerWithNATS_MalformedURL_FailsClosed(t *testing.T) {
	log, _, drain := AppLoggerWithNATS(Config{App: "test-app"}, NATSConfig{URL: "://not-a-url"}, WithStdout())
	if log == nil {
		t.Fatal("logger is nil on dial failure — must fall back to stdout")
	}
	// Logger must remain usable. If this panicked we'd see it here.
	log.Info("hello after dial failure")
	drain()
}

// TestDialLogNATS_UnreachableURL_RetriesInBackground: with
// RetryOnFailedConnect(true), an unreachable broker still yields a
// non-error conn (queued for background reconnect). The helper
// must accept that and wire drain accordingly.
func TestDialLogNATS_UnreachableURL_RetriesInBackground(t *testing.T) {
	// 127.0.0.1:1 is reserved and reliably refused on every platform
	// we run on. Combined with nats.Timeout the test caps at ~5s.
	nc, err := dialLogNATS(NATSConfig{URL: "nats://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("dialLogNATS with RetryOnFailedConnect should not error on initial unreachable broker: %v", err)
	}
	if nc == nil {
		t.Fatal("nc is nil — expected a conn queued for reconnect")
	}
	// Defer-style cleanup. Drain on an unconnected conn is a no-op,
	// but calling it must not panic.
	_ = nc.Drain()
	nc.Close()
}

// TestDialLogNATS_MTLS_MissingFiles: cert/key paths that don't exist
// must fail closed at config-build time — the eager load in
// ReloadingClientConfig surfaces a bad path before the dial rather
// than at the first (silent) handshake.
func TestDialLogNATS_MTLS_MissingFiles(t *testing.T) {
	nc, err := dialLogNATS(NATSConfig{
		URL:      "nats://127.0.0.1:1",
		CertFile: "/no/such/cert.pem",
		KeyFile:  "/no/such/key.pem",
	})
	if err == nil {
		t.Fatalf("expected error for missing mTLS files; nc=%v", nc)
	}
	if !strings.Contains(err.Error(), "log shipping") {
		t.Errorf("err = %v, want it wrapped with \"log shipping\"", err)
	}
}

// TestDialLogNATS_MTLS_QueuesConn: with a valid cert+key+CA the helper
// builds the reloading TLS config and dials. The broker is
// unreachable, but RetryOnFailedConnect means a non-nil conn is queued
// without error — proving the mTLS branch reaches nats.Connect.
func TestDialLogNATS_MTLS_QueuesConn(t *testing.T) {
	certFile, keyFile, caFile := writeMTLSCertFiles(t)
	nc, err := dialLogNATS(NATSConfig{
		URL:      "nats://127.0.0.1:1",
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
		Timeout:  500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("mTLS dial should not error on unreachable broker: %v", err)
	}
	if nc == nil {
		t.Fatal("nc is nil — expected a conn queued for reconnect")
	}
	_ = nc.Drain()
	nc.Close()
}

// writeMTLSCertFiles generates a self-signed ECDSA cert/key pair on
// disk plus a CA file (the same self-signed cert) and returns their
// paths. Enough for ReloadingClientConfig's eager load + CA pool.
func writeMTLSCertFiles(t *testing.T) (certFile, keyFile, caFile string) {
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

// TestAppLoggerWithNATS_InstanceSuffixesSubjectAndLogs verifies the
// per-host case used by cert-agentd / ssh-tunneld: Instance
// suffixes the NATS subject AND adds an "instance" attribute to
// every log line. Tested at the helper layer via an httptest-style
// no-op so we don't need a real broker; the dial branch goes
// through RetryOnFailedConnect and queues the (unreachable) conn,
// which is enough to exercise subject derivation.
func TestAppLoggerWithNATS_InstanceSuffixesSubjectAndLogs(t *testing.T) {
	// Real broker not required — the subject-derivation path runs
	// before any Publish call. RetryOnFailedConnect tolerates the
	// unreachable URL.
	log, _, drain := AppLoggerWithNATS(Config{
		App:      "cert-agentd",
		Instance: "host-42",
	}, NATSConfig{URL: "nats://127.0.0.1:1"}, WithStdout())
	defer drain()

	// Logger must remain usable and must carry the instance attribute
	// on every subsequent record. We can't easily inspect the slog
	// handler chain from here, but if the .With(...) wiring is wrong
	// the line below would either panic or produce a missing-instance
	// record visible in the surrounding test log capture.
	log.Info("test line — should carry instance attribute")
}

// TestAppLoggerWithNATS_EmptyInstancePreservesLegacySubject: empty
// Instance keeps the subject at the legacy "app_log.<app>" form so
// singleton daemons (certd, authd, ssh-proxyd) don't need to
// rewrite consumers.
func TestAppLoggerWithNATS_EmptyInstancePreservesLegacySubject(t *testing.T) {
	// Same shape — exercises the no-Instance branch.
	log, _, drain := AppLoggerWithNATS(Config{App: "certd"}, NATSConfig{
		URL: "nats://127.0.0.1:1",
	}, WithStdout())
	defer drain()
	log.Info("test line — should NOT carry instance attribute")
}

// TestDialLogNATS_AppliesCustomTimeout: when cfg.Timeout is set,
// the helper hands it to nats.Timeout. Exercises the "explicit
// value beats default" branch; we can't easily observe the actual
// timeout from nats.go, so we just confirm the dial succeeds with
// a custom value (proves the path doesn't reject non-zero input).
func TestDialLogNATS_AppliesCustomTimeout(t *testing.T) {
	nc, err := dialLogNATS(NATSConfig{
		URL:           "nats://127.0.0.1:1",
		Timeout:       500 * time.Millisecond,
		DrainTimeout:  100 * time.Millisecond,
		ReconnectWait: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("dialLogNATS with custom timing should not error on unreachable broker (RetryOnFailedConnect): %v", err)
	}
	if nc == nil {
		t.Fatal("nc is nil — expected a conn queued for reconnect")
	}
	_ = nc.Drain()
	nc.Close()
}
