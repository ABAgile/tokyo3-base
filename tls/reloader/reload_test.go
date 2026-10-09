package reloader_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/tls/reloader"
)

// mtimeOf returns path's current mtime, so a test can rewrite the file and
// restore that mtime.
func mtimeOf(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}

// rewriteKeepingMtime replaces path with data and restores mtime, the case the
// mtime gate cannot see.
func rewriteKeepingMtime(t *testing.T, path string, data []byte, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// A bundle rewritten with its old mtime is invisible to Pool but picked up by
// Reload.
func TestCALoader_ReloadBypassesMtimeGate(t *testing.T) {
	_, _, caA := writeCertKeyFiles(t)
	certB, _, caB := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caA, 0o600); err != nil {
		t.Fatal(err)
	}
	mtime := mtimeOf(t, caFile)

	loader := reloader.NewCALoader(caFile)
	before, err := loader.Pool()
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parseLeaf(t, certB)},
		ServerName:       "localhost",
	}
	if err := loader.VerifyConnection(cs); err == nil {
		t.Fatal("peer issued by CA B verified against CA A")
	}

	rewriteKeepingMtime(t, caFile, caB, mtime)
	if err := loader.VerifyConnection(cs); err == nil {
		t.Fatal("mtime gate: want stale pool before Reload")
	}
	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if pool, _ := loader.Pool(); pool == before {
		t.Fatal("Reload did not install the rewritten bundle")
	}
	if err := loader.VerifyConnection(cs); err != nil {
		t.Fatalf("verify after Reload: %v", err)
	}
}

// A forced reload of a bad file returns the error to its caller and keeps the
// previous pool live. OnError stays silent because the caller already has it.
func TestCALoader_ReloadFailureKeepsPool(t *testing.T) {
	_, _, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	loader := reloader.NewCALoader(caFile)
	before, err := loader.Pool()
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	reported := 0
	loader.OnError = func(error) { reported++ }

	future := time.Now().Add(2 * time.Second)
	rewriteKeepingMtime(t, caFile, []byte("not pem"), future)
	if err := loader.Reload(); err == nil {
		t.Fatal("Reload of a corrupt bundle returned nil")
	}
	if reported != 0 {
		t.Errorf("OnError fired %d times on forced Reload, want 0", reported)
	}
	if pool, err := loader.Pool(); err != nil || pool != before {
		t.Fatalf("previous pool not kept: pool=%p err=%v", pool, err)
	}
}

// Refresh re-reads CA pools as well as the cert pair. This covers a CA-only
// rotation that keeps its old mtime.
func TestReloader_RefreshReloadsCAPools(t *testing.T) {
	certA, keyA, caA := writeCertKeyFiles(t)
	certB, _, caB := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caA, 0o600); err != nil {
		t.Fatal(err)
	}
	mtime := mtimeOf(t, caFile)

	r, err := reloader.New(reloader.Config{
		CertPath: certA,
		KeyPath:  keyA,
		Pools:    map[string]string{"ca": caFile},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parseLeaf(t, certB)},
		ServerName:       "localhost",
	}
	verify := r.VerifyConnection("ca")
	if err := verify(cs); err == nil {
		t.Fatal("peer issued by CA B verified against CA A")
	}

	rewriteKeepingMtime(t, caFile, caB, mtime)
	if err := r.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if err := verify(cs); err != nil {
		t.Fatalf("verify after Refresh: %v", err)
	}
}
