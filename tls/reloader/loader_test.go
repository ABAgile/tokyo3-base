package reloader_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/abagile/tokyo3-base/tls/reloader"
)

// writeCertKeyFiles generates an ECDSA P-256 self-signed cert and writes PEM
// cert + key to temp files, returning their paths (and the cert PEM, which
// doubles as a single-cert CA bundle since the cert is self-signed).
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

// overwrite copies the contents of src into dst (both PEM file paths).
func overwrite(t *testing.T, dst, src string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

// ── CertLoader ────────────────────────────────────────────────────────────────

func TestCertLoader_GetCertificate(t *testing.T) {
	loader := reloader.NewCertLoader("/nonexistent/cert.pem", "/nonexistent/key.pem")
	_, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err == nil {
		t.Error("expected error for nonexistent cert files")
	}
}

func TestCertLoader_WithRealFiles(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)

	loader := reloader.NewCertLoader(certFile, keyFile)
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

	loader := reloader.NewCertLoader(certFile, keyFile)
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
	loader := reloader.NewCertLoader(certFile, keyFile)

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
	loader := reloader.NewCertLoader(certFile, keyFile)

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

// TestCertLoader_GetClientCertificate verifies the client-side
// callback shares CertLoader's load logic: it returns a cert and
// picks up an in-place rotation when the cert file's mtime advances.
func TestCertLoader_GetClientCertificate(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)
	loader := reloader.NewCertLoader(certFile, keyFile)

	first, err := loader.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("first GetClientCertificate: %v", err)
	}
	if first == nil || len(first.Certificate) == 0 {
		t.Fatal("expected non-nil certificate")
	}

	// Write a fresh pair over the same paths, advance mtime, expect reload.
	newCert, newKey, _ := writeCertKeyFiles(t)
	overwrite(t, certFile, newCert)
	overwrite(t, keyFile, newKey)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatal(err)
	}

	second, err := loader.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("second GetClientCertificate: %v", err)
	}
	if second == first {
		t.Error("expected reloaded cert pointer after mtime advance")
	}
}

// TestCertLoader_Reload_BypassesMtimeGate: a rotation whose write
// doesn't advance the file mtime (same-second coalescing) is invisible
// to the lazy path — the forced Reload must pick it up anyway. This is
// the contract Reloader.Refresh is built on.
func TestCertLoader_Reload_BypassesMtimeGate(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)
	loader := reloader.NewCertLoader(certFile, keyFile)

	first, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	origStat, err := os.Stat(certFile)
	if err != nil {
		t.Fatal(err)
	}

	// Rotate in place, then pin mtime back to the original value so
	// the lazy path sees "unchanged".
	newCert, newKey, _ := writeCertKeyFiles(t)
	overwrite(t, certFile, newCert)
	overwrite(t, keyFile, newKey)
	if err := os.Chtimes(certFile, origStat.ModTime(), origStat.ModTime()); err != nil {
		t.Fatal(err)
	}

	lazy, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("lazy load: %v", err)
	}
	if lazy != first {
		t.Fatal("lazy path reloaded despite unchanged mtime — mtime gate broken, test premise invalid")
	}

	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	forced, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("post-Reload load: %v", err)
	}
	if forced == first {
		t.Error("Reload did not swap the cert")
	}
}

// TestCertLoader_Hooks: OnSwap fires on every successful load (initial
// + rotation) with the file mtime; OnError fires when a lazy reload
// attempt fails while the previous cert stays live. These hooks are
// the Reloader's logging seam.
func TestCertLoader_Hooks(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)
	loader := reloader.NewCertLoader(certFile, keyFile)
	var swaps, errs int
	loader.OnSwap = func(cert *tls.Certificate, mtime time.Time) {
		swaps++
		if cert == nil || mtime.IsZero() {
			t.Errorf("OnSwap cert=%v mtime=%v, want non-nil cert and real mtime", cert, mtime)
		}
	}
	loader.OnError = func(err error) {
		errs++
		if err == nil {
			t.Error("OnError called with nil error")
		}
	}

	if _, err := loader.GetCertificate(&tls.ClientHelloInfo{}); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if swaps != 1 {
		t.Errorf("swaps after initial load = %d, want 1", swaps)
	}

	// Rotate with an mtime bump — lazy path swaps, OnSwap fires again.
	newCert, newKey, _ := writeCertKeyFiles(t)
	overwrite(t, certFile, newCert)
	overwrite(t, keyFile, newKey)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := loader.GetCertificate(&tls.ClientHelloInfo{}); err != nil {
		t.Fatalf("post-rotation load: %v", err)
	}
	if swaps != 2 {
		t.Errorf("swaps after rotation = %d, want 2", swaps)
	}

	// Corrupt drop-in with an mtime bump — lazy path keeps the old
	// cert, OnError fires.
	if err := os.WriteFile(certFile, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	future = future.Add(2 * time.Second)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatal(err)
	}
	cert, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || cert == nil {
		t.Fatalf("stale fallback: cert=%v err=%v", cert, err)
	}
	if errs != 1 {
		t.Errorf("errs after corrupt drop-in = %d, want 1", errs)
	}
	if swaps != 2 {
		t.Errorf("swaps after corrupt drop-in = %d, want 2 (no swap)", swaps)
	}
}

// ── CALoader ──────────────────────────────────────────────────────────────────

// TestCALoader_VerifyConnection_LivePool proves the CA pool is read
// live: a peer that verifies against the initial bundle must stop
// verifying after the bundle is rotated to a different CA in place —
// the exact behavior a frozen RootCAs cannot provide.
func TestCALoader_VerifyConnection_LivePool(t *testing.T) {
	certA, _, caAPEM := writeCertKeyFiles(t)
	_, _, caBPEM := writeCertKeyFiles(t)

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caAPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	pemData, err := os.ReadFile(certA)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	peer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse peer cert: %v", err)
	}
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{peer},
		ServerName:       "localhost",
	}

	loader := reloader.NewCALoader(caFile)
	if err := loader.VerifyConnection(cs); err != nil {
		t.Fatalf("verify against original CA: %v", err)
	}

	// Rotate the bundle to an unrelated CA; bump mtime for coarse
	// filesystems. The same peer must now fail verification.
	if err := os.WriteFile(caFile, caBPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(caFile, future, future); err != nil {
		t.Fatal(err)
	}
	if err := loader.VerifyConnection(cs); err == nil {
		t.Error("peer still verifies after CA rotation — pool is frozen, not live")
	}
}

// TestCALoader_KeepsPoolAcrossFailedReload: a corrupt drop-in (or a
// rotation caught mid-write) must not open a trust window or kill
// reconnects — the previous pool stays live.
func TestCALoader_KeepsPoolAcrossFailedReload(t *testing.T) {
	certA, _, caAPEM := writeCertKeyFiles(t)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caAPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	loader := reloader.NewCALoader(caFile)
	if _, err := loader.Pool(); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	if err := os.WriteFile(caFile, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(caFile, future, future); err != nil {
		t.Fatal(err)
	}

	pool, err := loader.Pool()
	if err != nil || pool == nil {
		t.Fatalf("Pool after corrupt drop-in: pool=%v err=%v, want previous pool kept", pool, err)
	}

	// The kept pool must still verify the original peer.
	pemData, err := os.ReadFile(certA)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	peer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{peer},
		ServerName:       "localhost",
	}
	if err := loader.VerifyConnection(cs); err != nil {
		t.Errorf("verify with kept pool: %v", err)
	}
}

// TestCALoader_Hooks mirrors TestCertLoader_Hooks for the trust side:
// OnSwap receives the raw PEM (the reloader fingerprints it), OnError
// fires on a corrupt drop-in while the previous pool stays live.
func TestCALoader_Hooks(t *testing.T) {
	_, _, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	loader := reloader.NewCALoader(caFile)
	var swaps, errs int
	loader.OnSwap = func(raw []byte, mtime time.Time) {
		swaps++
		if len(raw) == 0 || mtime.IsZero() {
			t.Errorf("OnSwap raw len=%d mtime=%v, want PEM bytes and real mtime", len(raw), mtime)
		}
	}
	loader.OnError = func(err error) {
		errs++
		if err == nil {
			t.Error("OnError called with nil error")
		}
	}

	if _, err := loader.Pool(); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if swaps != 1 {
		t.Errorf("swaps after initial load = %d, want 1", swaps)
	}

	if err := os.WriteFile(caFile, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(caFile, future, future); err != nil {
		t.Fatal(err)
	}
	pool, err := loader.Pool()
	if err != nil || pool == nil {
		t.Fatalf("stale fallback: pool=%v err=%v", pool, err)
	}
	if errs != 1 {
		t.Errorf("errs after corrupt drop-in = %d, want 1", errs)
	}
	if swaps != 1 {
		t.Errorf("swaps after corrupt drop-in = %d, want 1 (no swap)", swaps)
	}
}

// ── ClientConfig ──────────────────────────────────────────────────────────────

func TestClientConfig_RequiresCertAndKey(t *testing.T) {
	if _, err := reloader.ClientConfig("", "", ""); err == nil {
		t.Fatal("expected error when cert and key are empty")
	}
	certFile, _, _ := writeCertKeyFiles(t)
	if _, err := reloader.ClientConfig(certFile, "", ""); err == nil {
		t.Fatal("expected error when key is missing")
	}
}

func TestClientConfig_FailsClosedOnMissingCert(t *testing.T) {
	if _, err := reloader.ClientConfig("/no/such/cert.pem", "/no/such/key.pem", ""); err == nil {
		t.Fatal("expected error for nonexistent cert/key (eager load)")
	}
}

func TestClientConfig_FailsClosedOnMissingCA(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)
	if _, err := reloader.ClientConfig(certFile, keyFile, "/no/such/ca.pem"); err == nil {
		t.Fatal("expected error for nonexistent CA file (eager load)")
	}
}

// TestClientConfig_WiresCallbackAndCA confirms the returned config
// carries no static Certificates (the callback is the source of
// truth), verifies servers against the live CA pool (via
// VerifyConnection + InsecureSkipVerify, not a frozen RootCAs), and
// reloads the leaf when the cert file is rotated in place.
func TestClientConfig_WiresCallbackAndCA(t *testing.T) {
	certFile, keyFile, caPEM := writeCertKeyFiles(t)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	cfg, err := reloader.ClientConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	if len(cfg.Certificates) != 0 {
		t.Error("expected no static Certificates; the callback supplies the leaf")
	}
	if cfg.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate not wired")
	}
	if cfg.RootCAs != nil {
		t.Error("RootCAs set — a frozen pool defeats CA hot-reload")
	}
	if cfg.VerifyConnection == nil || !cfg.InsecureSkipVerify {
		t.Error("VerifyConnection + InsecureSkipVerify not wired for live-pool verification")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}

	first, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("callback first call: %v", err)
	}

	newCert, newKey, _ := writeCertKeyFiles(t)
	overwrite(t, certFile, newCert)
	overwrite(t, keyFile, newKey)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatal(err)
	}

	second, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("callback after rotation: %v", err)
	}
	if second == first {
		t.Error("expected callback to surface the rotated leaf")
	}
}

// ── NewClientCALoader ─────────────────────────────────────────────────────────

func TestNewClientCALoader_FailsClosedOnMissingFile(t *testing.T) {
	cfg := &tls.Config{}
	if _, err := reloader.NewClientCALoader(cfg, "/no/such/ca.pem", tls.RequireAndVerifyClientCert); err == nil {
		t.Fatal("expected error for nonexistent client-CA file (eager load)")
	}
}

// TestNewClientCALoader_WiresAndReloads confirms the helper seeds
// ClientAuth + ClientCAs, installs a non-recursive GetConfigForClient,
// and that the per-handshake config reflects a client-CA bundle rotated
// in place — a peer that verified against the original bundle stops
// verifying against the rotated one.
func TestNewClientCALoader_WiresAndReloads(t *testing.T) {
	certA, _, caAPEM := writeCertKeyFiles(t)
	_, _, caBPEM := writeCertKeyFiles(t)

	caFile := filepath.Join(t.TempDir(), "client-ca.pem")
	if err := os.WriteFile(caFile, caAPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	cfg := &tls.Config{}
	loader, err := reloader.NewClientCALoader(cfg, caFile, tls.VerifyClientCertIfGiven)
	if err != nil {
		t.Fatalf("NewClientCALoader: %v", err)
	}
	if loader == nil {
		t.Fatal("expected non-nil CALoader")
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs not seeded")
	}
	if cfg.GetConfigForClient == nil {
		t.Fatal("GetConfigForClient not wired")
	}

	// Parse the peer that chains to CA-A (self-signed, so it is CA-A).
	block, _ := pem.Decode(caAPEM)
	peerA, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse peer: %v", err)
	}
	csA := tls.ConnectionState{PeerCertificates: []*x509.Certificate{peerA}, ServerName: "localhost"}
	_ = certA

	// Per-handshake config verifies peerA against the initial CA-A pool.
	c1, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	if c1.GetConfigForClient != nil {
		t.Error("clone still has GetConfigForClient set — recursion risk")
	}
	if err := btls.VerifyPeerChain(c1.ClientCAs, csA); err != nil {
		t.Fatalf("peerA should verify against initial CA-A pool: %v", err)
	}

	// Rotate the bundle to an unrelated CA-B in place; bump mtime.
	if err := os.WriteFile(caFile, caBPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(caFile, future, future); err != nil {
		t.Fatal(err)
	}

	// The next handshake's config carries the CA-B pool — peerA no longer verifies.
	c2, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient after rotation: %v", err)
	}
	if err := btls.VerifyPeerChain(c2.ClientCAs, csA); err == nil {
		t.Error("peerA still verifies after client-CA rotation — pool not live")
	}
}

// TestCALoader_WireClientCAs_FiresHookOnInitialLoad confirms the method
// path: creating the loader, setting OnSwap, then calling WireClientCAs
// fires the hook on the eager initial load — the reason the method is
// public rather than only reachable via NewClientCALoader (whose eager
// load happens before the caller can attach hooks).
func TestCALoader_WireClientCAs_FiresHookOnInitialLoad(t *testing.T) {
	_, _, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "client-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	loader := reloader.NewCALoader(caFile)
	var swaps int
	loader.OnSwap = func(_ []byte, _ time.Time) { swaps++ }

	cfg := &tls.Config{}
	if err := loader.WireClientCAs(cfg, tls.RequireAndVerifyClientCert); err != nil {
		t.Fatalf("WireClientCAs: %v", err)
	}
	if swaps != 1 {
		t.Errorf("OnSwap fired %d times on initial load, want 1", swaps)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.ClientCAs == nil || cfg.GetConfigForClient == nil {
		t.Errorf("cfg not fully wired: auth=%v clientCAs=%v getCfg=%v", cfg.ClientAuth, cfg.ClientCAs != nil, cfg.GetConfigForClient != nil)
	}
}
