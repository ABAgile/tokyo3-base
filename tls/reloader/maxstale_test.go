package reloader_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/tls/reloader"
)

// A CA file removed while a pool is kept is reported once, not on every
// handshake.
func TestCALoader_StatFailureReportedOnce(t *testing.T) {
	_, _, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	loader := reloader.NewCALoader(caFile)
	reported := 0
	loader.OnError = func(error) { reported++ }
	want, err := loader.Pool()
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	if err := os.Remove(caFile); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		pool, err := loader.Pool()
		if err != nil || pool != want {
			t.Fatalf("Pool with file removed: pool=%p err=%v, want kept pool", pool, err)
		}
	}
	if reported != 1 {
		t.Errorf("OnError fired %d times across 5 calls, want 1", reported)
	}
}

// With MaxStale set, a bundle that stays unloadable past the window stops
// being trusted, and trust returns once a good bundle lands.
func TestCALoader_MaxStaleFailsClosed(t *testing.T) {
	_, _, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	loader := reloader.NewCALoader(caFile)
	loader.MaxStale = 100 * time.Millisecond
	if _, err := loader.Pool(); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	rewriteCA(t, caFile)
	if _, err := loader.Pool(); err != nil {
		t.Fatalf("within MaxStale: want last good pool kept, got %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if pool, err := loader.Pool(); err == nil {
		t.Fatalf("past MaxStale: got pool %p, want error", pool)
	}

	good := time.Now().Add(4 * time.Second)
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(caFile, good, good); err != nil {
		t.Fatal(err)
	}
	if _, err := loader.Pool(); err != nil {
		t.Fatalf("after good bundle restored: %v", err)
	}
}

// Config.CAMaxStale reaches the file-backed pools the Reloader builds.
func TestReloader_CAMaxStaleWired(t *testing.T) {
	certFile, keyFile, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := reloader.New(reloader.Config{
		CertPath:   certFile,
		KeyPath:    keyFile,
		Pools:      map[string]string{"ca": caFile},
		CAMaxStale: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parseLeaf(t, certFile)},
		ServerName:       "localhost",
	}
	verify := r.VerifyConnection("ca")
	if err := verify(cs); err != nil {
		t.Fatalf("verify with good bundle: %v", err)
	}

	// The window starts at the first failed reload the loader observes, so
	// observe one (as the next handshake would) before waiting it out.
	rewriteCA(t, caFile)
	if err := verify(cs); err != nil {
		t.Fatalf("within CAMaxStale: want last good bundle kept, got %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if err := verify(cs); err == nil {
		t.Fatal("verify past CAMaxStale with unloadable bundle: want fail closed")
	}
}

func parseLeaf(t *testing.T, certFile string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block in cert file")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
