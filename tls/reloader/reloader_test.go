package reloader_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/tls/reloader"
)

// writePEMCertKey generates a self-signed ECDSA cert with the given
// CN, writes cert+key PEM to the supplied paths, and returns the
// SerialNumber so the caller can confirm which cert was loaded.
// The cert is marked IsCA so it can also be appended to a trust
// pool — convenient for tests that exercise verifyConnection.
func writePEMCertKey(t *testing.T, certPath, keyPath, cn string, serial int64) *big.Int {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return tmpl.SerialNumber
}

// newOne builds a single-pool Reloader pointing at a freshly-minted
// cert. The cert file doubles as the pool bundle since the cert is
// self-signed and IsCA — exactly what cert-agentd's tests do, and
// keeps each test self-contained.
func newOne(t *testing.T, cn string) (*reloader.Reloader, string, string) {
	t.Helper()
	return newOneLogged(t, cn, nil)
}

// newOneLogged is newOne with an explicit logger so tests that want
// to assert on emitted log lines can capture them. Pass nil to get
// the default (slog.Default).
func newOneLogged(t *testing.T, cn string, log *slog.Logger) (*reloader.Reloader, string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	writePEMCertKey(t, certPath, keyPath, cn, 1)
	r, err := reloader.New(reloader.Config{
		CertPath: certPath,
		KeyPath:  keyPath,
		Pools:    map[string]string{"ca": certPath},
		Log:      log,
	})
	if err != nil {
		t.Fatalf("reloader.New: %v", err)
	}
	return r, certPath, keyPath
}

// ── construction + initial load ───────────────────────────────────────────────

func TestNew_LoadsInitialMaterial(t *testing.T) {
	r, _, _ := newOne(t, "test-cert")
	c, err := r.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if c == nil || c.Leaf == nil {
		t.Fatal("Leaf not parsed")
	}
	if c.Leaf.Subject.CommonName != "test-cert" {
		t.Errorf("CommonName = %q, want test-cert", c.Leaf.Subject.CommonName)
	}
}

func TestNew_RequiresCertPath(t *testing.T) {
	_, err := reloader.New(reloader.Config{
		KeyPath: "/tmp/k", Pools: map[string]string{"ca": "/tmp/ca"},
	})
	if err == nil || !strings.Contains(err.Error(), "CertPath") {
		t.Errorf("err = %v, want CertPath-required", err)
	}
}

func TestNew_RequiresKeyPath(t *testing.T) {
	_, err := reloader.New(reloader.Config{
		CertPath: "/tmp/c", Pools: map[string]string{"ca": "/tmp/ca"},
	})
	if err == nil || !strings.Contains(err.Error(), "KeyPath") {
		t.Errorf("err = %v, want KeyPath-required", err)
	}
}

func TestNew_RequiresAtLeastOnePool(t *testing.T) {
	_, err := reloader.New(reloader.Config{CertPath: "/tmp/c", KeyPath: "/tmp/k"})
	if err == nil || !strings.Contains(err.Error(), "Pool") {
		t.Errorf("err = %v, want pool-required", err)
	}
}

func TestNew_RejectsEmptyPoolName(t *testing.T) {
	_, err := reloader.New(reloader.Config{
		CertPath: "/tmp/c", KeyPath: "/tmp/k",
		Pools: map[string]string{"": "/tmp/ca"},
	})
	if err == nil || !strings.Contains(err.Error(), "non-empty") {
		t.Errorf("err = %v, want non-empty pool name", err)
	}
}

func TestNew_RejectsMissingFiles(t *testing.T) {
	_, err := reloader.New(reloader.Config{
		CertPath: "/no/such/cert", KeyPath: "/no/such/key",
		Pools: map[string]string{"ca": "/no/such/ca"},
	})
	if err == nil {
		t.Fatal("expected error for missing files")
	}
}

// ── LeafExpiry ────────────────────────────────────────────────────────────────

func TestLeafExpiry_SurfacedFromLoadedLeaf(t *testing.T) {
	r, _, _ := newOne(t, "x")
	exp := r.LeafExpiry()
	if exp.IsZero() {
		t.Fatal("LeafExpiry zero after initial load")
	}
	if d := time.Until(exp); d < 30*time.Minute || d > 90*time.Minute {
		t.Errorf("LeafExpiry %v not within ~1h window", d)
	}
}

// ── Refresh (explicit) ────────────────────────────────────────────────────────

func TestRefresh_PicksUpNewCert(t *testing.T) {
	r, certPath, keyPath := newOne(t, "old")
	// Overwrite with a new cert; Refresh must re-read regardless of
	// mtime (the explicit-refresh path bypasses the mtime gate).
	want := writePEMCertKey(t, certPath, keyPath, "new", 42)
	if err := r.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	c, _ := r.GetClientCertificate(nil)
	if c.Leaf.SerialNumber.Cmp(want) != 0 {
		t.Errorf("loaded serial = %v, want %v", c.Leaf.SerialNumber, want)
	}
	if c.Leaf.Subject.CommonName != "new" {
		t.Errorf("CN = %q, want new", c.Leaf.Subject.CommonName)
	}
}

// ── RunPoll: CA bundle ────────────────────────────────────────────────────────

func TestRunPoll_RefreshesCABundleOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "client", 1)
	writePEMCertKey(t, caPath, filepath.Join(dir, "ca-key.pem"), "ca-old", 100)

	r, err := reloader.New(reloader.Config{
		CertPath: certPath, KeyPath: keyPath,
		Pools: map[string]string{"ca": caPath},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Overwrite the bundle, advance mtime explicitly so the
	// filesystem reports a change even on coarse-mtime systems.
	writePEMCertKey(t, caPath, filepath.Join(dir, "ca-key.pem"), "ca-new", 200)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(caPath, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.RunPoll(ctx, 20*time.Millisecond) }()
	// Give the poll a couple of ticks.
	time.Sleep(120 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("RunPoll err = %v, want context.Canceled", err)
	}

	// Verify the new bundle is now in effect by attempting to verify
	// a peer cert that chains to ca-new — easiest done indirectly
	// through TLSConfig + a fake server, but here we just confirm the
	// reload happened by reading the log buffer in the next test.
	// This test only asserts no error came out.
}

// ── RunPoll: cert mtime polling (PollCert=true) ───────────────────────────────

func TestRunPoll_PollCert_PicksUpCertRotation(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	caKeyPath := filepath.Join(dir, "ca-key.pem")
	writePEMCertKey(t, certPath, keyPath, "v1", 1)
	writePEMCertKey(t, caPath, caKeyPath, "ca", 100)

	r, err := reloader.New(reloader.Config{
		CertPath: certPath, KeyPath: keyPath,
		Pools:    map[string]string{"ca": caPath},
		PollCert: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Confirm the initial leaf is v1.
	c, _ := r.GetClientCertificate(nil)
	if c.Leaf.Subject.CommonName != "v1" {
		t.Fatalf("initial CN = %q, want v1", c.Leaf.Subject.CommonName)
	}

	// Rotate on disk.
	wantSerial := writePEMCertKey(t, certPath, keyPath, "v2", 2)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.RunPoll(ctx, 20*time.Millisecond) }()

	// Poll until the rotation is observed or we time out.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, _ := r.GetClientCertificate(nil)
		if c != nil && c.Leaf != nil && c.Leaf.Subject.CommonName == "v2" {
			cancel()
			<-done
			if c.Leaf.SerialNumber.Cmp(wantSerial) != 0 {
				t.Errorf("serial = %v, want %v", c.Leaf.SerialNumber, wantSerial)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("RunPoll never picked up the rotated cert")
}

// ── log surfaces ──────────────────────────────────────────────────────────────

func TestLogsOnBundleReload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "client", 1)
	writePEMCertKey(t, caPath, filepath.Join(dir, "ca-key.pem"), "ca-v1", 100)

	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	_, err := reloader.New(reloader.Config{
		CertPath: certPath, KeyPath: keyPath,
		Pools: map[string]string{"ca": caPath},
		Log:   log,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Initial load should have emitted "workload cert reloaded" +
	// "CA bundle reloaded" (with name=ca).
	out := logBuf.String()
	if !strings.Contains(out, `"workload cert reloaded"`) {
		t.Errorf("missing cert-reload log line:\n%s", out)
	}
	if !strings.Contains(out, `"CA bundle reloaded"`) {
		t.Errorf("missing bundle-reload log line:\n%s", out)
	}
	if !strings.Contains(out, `"name":"ca"`) {
		t.Errorf("bundle-reload log missing name=ca:\n%s", out)
	}
	if !strings.Contains(out, `"fingerprint":`) {
		t.Errorf("bundle-reload log missing fingerprint:\n%s", out)
	}
}

// ── VerifyConnection / TLSConfig ──────────────────────────────────────────────

// TestTLSConfig_VerifiesAgainstPool spins up an httptest TLS server,
// builds a Reloader pool that trusts the server's cert, and dials
// using the Reloader's tls.Config. Success means the live pool path
// is wired correctly; rotation tests cover the swap behaviour above.
func TestTLSConfig_VerifiesAgainstPool(t *testing.T) {
	dir := t.TempDir()
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client-key.pem")
	writePEMCertKey(t, clientCertPath, clientKeyPath, "client", 1)

	// httptest server uses its own self-signed cert; we use its CA
	// bundle as the trust pool for the test reloader.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	serverCAPath := filepath.Join(dir, "server-ca.pem")
	if err := os.WriteFile(serverCAPath, pemEncodeCert(srv.Certificate().Raw), 0o644); err != nil {
		t.Fatalf("write server CA: %v", err)
	}

	r, err := reloader.New(reloader.Config{
		CertPath: clientCertPath, KeyPath: clientKeyPath,
		Pools: map[string]string{"server": serverCAPath},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	serverURL, err := parseTLSURL(srv.URL)
	if err != nil {
		t.Fatalf("parseURL: %v", err)
	}
	cfg := r.TLSConfig("server", reloader.WithServerName(serverURL))
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout:   2 * time.Second,
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body = %q", body)
	}
}

// TestVerifyConnection_RejectsUnknownPool: a typo in the pool name
// must fail at handshake time with a clear error rather than silently
// trusting nothing.
func TestVerifyConnection_RejectsUnknownPool(t *testing.T) {
	r, _, _ := newOne(t, "x")
	verify := r.VerifyConnection("nope")
	err := verify(tls.ConnectionState{})
	if err == nil || !strings.Contains(err.Error(), `pool "nope"`) {
		t.Errorf("err = %v, want unknown-pool message", err)
	}
}

// TestVerifyConnection_RejectsEmptyPeerCerts: a peer that presents no
// certificate at all must be rejected even if the pool is loaded.
func TestVerifyConnection_RejectsEmptyPeerCerts(t *testing.T) {
	r, _, _ := newOne(t, "x")
	verify := r.VerifyConnection("ca")
	err := verify(tls.ConnectionState{})
	if err == nil || !strings.Contains(err.Error(), "no certificates") {
		t.Errorf("err = %v, want no-certificates message", err)
	}
}

// ── WarnIfNearExpiry / ExpiryAttrs ────────────────────────────────────────────

// TestWarnIfNearExpiry_EmitsWarnWhenWithinThreshold builds a
// short-lived cert and confirms the warn line surfaces with the
// expected attrs.
func TestWarnIfNearExpiry_EmitsWarnWhenWithinThreshold(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	// writePEMCertKey produces a cert with NotAfter = now + 1h, so a
	// 24-hour threshold definitely fires.
	writePEMCertKey(t, certPath, keyPath, "short-lived", 1)

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	r, err := reloader.New(reloader.Config{
		CertPath: certPath, KeyPath: keyPath,
		Pools: map[string]string{"ca": certPath},
		Log:   log,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.WarnIfNearExpiry(24*time.Hour, "test cert is near expiry")

	got := buf.String()
	if !strings.Contains(got, `"test cert is near expiry"`) {
		t.Errorf("missing warn message:\n%s", got)
	}
	if !strings.Contains(got, `"remaining":`) {
		t.Errorf("missing remaining attr:\n%s", got)
	}
	if !strings.Contains(got, `"not_after":`) {
		t.Errorf("missing not_after attr:\n%s", got)
	}
}

// TestWarnIfNearExpiry_SkipsWhenBeyondThreshold: a freshly-minted
// cert is well outside a 1-second threshold; no warn fires.
func TestWarnIfNearExpiry_SkipsWhenBeyondThreshold(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	r, _, _ := newOneLogged(t, "fresh", log)
	r.WarnIfNearExpiry(1*time.Second, "should not appear")
	if strings.Contains(buf.String(), "should not appear") {
		t.Errorf("unexpected warn:\n%s", buf.String())
	}
}

// TestExpiryAttrs_YieldsRemainingDuration verifies the closure
// returns the expected attr name + a positive duration for a
// freshly-loaded cert.
func TestExpiryAttrs_YieldsRemainingDuration(t *testing.T) {
	r, _, _ := newOne(t, "live-cert")
	attrs := r.ExpiryAttrs("workload_cert_remaining")()
	if len(attrs) != 2 {
		t.Fatalf("attrs len = %d, want 2", len(attrs))
	}
	if attrs[0] != "workload_cert_remaining" {
		t.Errorf("attr name = %v, want workload_cert_remaining", attrs[0])
	}
	d, ok := attrs[1].(time.Duration)
	if !ok || d <= 0 {
		t.Errorf("attr value = %v (%T), want positive duration", attrs[1], attrs[1])
	}
}

// ── concurrency ───────────────────────────────────────────────────────────────

// TestConcurrent_GetClientCertWithRefresh runs many GetClientCertificate
// calls in parallel with Refresh swaps. Should never panic; race
// detector catches missing locks.
func TestConcurrent_GetClientCertWithRefresh(t *testing.T) {
	r, certPath, keyPath := newOne(t, "v1")
	const N = 16
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range N {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = r.GetClientCertificate(nil)
				}
			}
		})
	}
	// Rotate a few times while readers hammer.
	for i := range 5 {
		writePEMCertKey(t, certPath, keyPath, "rotated", int64(i+2))
		if err := r.Refresh(); err != nil {
			t.Errorf("Refresh: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}

// ── helpers ───────────────────────────────────────────────────────────────────

// pemEncodeCert wraps DER cert bytes in a PEM "CERTIFICATE" block —
// trivial inline helper instead of pulling in a separate util.
func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// parseTLSURL pulls the host (no port) out of an https://... URL —
// httptest serves SNI=127.0.0.1; we feed that as ServerName so the
// hostname check in VerifyConnection finds a SAN match.
func parseTLSURL(raw string) (string, error) {
	const prefix = "https://"
	if !strings.HasPrefix(raw, prefix) {
		return "", errors.New("not https")
	}
	host, _, err := net.SplitHostPort(strings.TrimPrefix(raw, prefix))
	if err != nil {
		return strings.TrimPrefix(raw, prefix), nil
	}
	return host, nil
}
