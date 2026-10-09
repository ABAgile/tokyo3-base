package reloader_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/tls/reloader"
)

// syncBuf is a goroutine-safe log sink: RunPoll logs from its own goroutine
// while the test waits for a line.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A CA pool that is configured but cannot be loaded at startup is a startup
// error. The process must not come up with a missing trust bundle.
func TestNew_UnloadableCABundleFailsStartup(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	writePEMCertKey(t, certPath, keyPath, "client", 1)

	_, err := reloader.New(reloader.Config{
		CertPath: certPath, KeyPath: keyPath,
		Pools: map[string]string{"edge": filepath.Join(dir, "missing-ca.pem")},
	})
	if err == nil || !strings.Contains(err.Error(), `initial pool "edge"`) {
		t.Fatalf("err = %v, want an initial-pool error for the missing bundle", err)
	}
}

func TestPoolNames_ListsEveryConfiguredPool(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	writePEMCertKey(t, certPath, keyPath, "client", 1)
	caFile, _ := writeCAFile(t, dir)

	r, err := reloader.New(reloader.Config{
		CertPath: certPath, KeyPath: keyPath,
		Pools: map[string]string{"system": "", "edge": caFile},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := r.PoolNames()
	slices.Sort(got)
	if want := []string{"edge", "system"}; !slices.Equal(got, want) {
		t.Errorf("PoolNames = %v, want %v", got, want)
	}
}

// A non-positive poll interval must not panic the ticker. The loop runs until
// its context ends. The default's value is not observable here, so this test
// does not pin it.
func TestRunPoll_NonPositiveIntervalUsesDefault(t *testing.T) {
	r, _, _ := newOne(t, "poll-default")
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := r.RunPoll(ctx, 0); err != context.DeadlineExceeded {
		t.Errorf("RunPoll(0) = %v, want the context deadline (the loop ran)", err)
	}
}

// A CA bundle rewritten with garbage must not replace the trusted pool. The
// poll loop logs the failure and keeps running.
func TestRunPoll_BrokenCABundleKeepsPoolAndWarns(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	writePEMCertKey(t, certPath, keyPath, "client", 1)
	caFile, _ := writeCAFile(t, dir)

	logs := &syncBuf{}
	r, err := reloader.New(reloader.Config{
		CertPath: certPath, KeyPath: keyPath,
		Pools: map[string]string{"edge": caFile},
		Log:   slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.RunPoll(ctx, 10*time.Millisecond) }()
	rewriteCA(t, caFile)

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "keeping previous pool") {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("broken bundle never reported:\n%s", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

// A client-CA bundle that cannot be loaded at startup stops the server from
// starting. It must not start without its client verification.
func TestServerTLS_UnloadableClientCAFails(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)
	missing := filepath.Join(t.TempDir(), "absent-ca.pem")

	_, err := reloader.ServerTLS(reloader.ServerTLSConfig{
		CertFile: certFile, KeyFile: keyFile, ClientCAFile: missing, Log: discard(),
	})
	if err == nil || !strings.Contains(err.Error(), "client CA") {
		t.Fatalf("err = %v, want a client-CA load error", err)
	}
}

// A client-CA bundle that breaks after startup keeps the previous pool. The
// handshake still succeeds, and the failure is logged.
func TestServerTLS_BrokenClientCAKeepsPoolAndWarns(t *testing.T) {
	certFile, keyFile, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	cfg, err := reloader.ServerTLS(reloader.ServerTLSConfig{
		CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile,
		Log: slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}

	rewriteCA(t, caFile)
	// The next handshake re-reads the bundle; the broken rewrite must not
	// fail the handshake.
	got, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient after a broken rewrite: %v", err)
	}
	if got == nil || got.ClientCAs == nil {
		t.Error("handshake lost the previous client-CA pool")
	}
	if !strings.Contains(logs.String(), "client CA hot-reload kept previous pool") {
		t.Errorf("broken client CA not logged:\n%s", logs.String())
	}
}

// Verification must fail closed when the CA bundle was never loaded, rather
// than verifying against an empty pool.
func TestCALoader_VerifyConnectionFailsWithoutPool(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent-ca.pem")
	l := reloader.NewCALoader(missing)
	if err := l.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("VerifyConnection passed with no CA bundle loaded")
	}
}

// rewriteCA replaces the bundle with garbage and moves its mtime forward. Some
// filesystems have coarse mtime granularity, and the loader re-reads a bundle
// only when its mtime advances.
func rewriteCA(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

// writeCAFile writes a CA bundle to dir and returns its path and contents.
func writeCAFile(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	_, _, caPEM := writeCertKeyFiles(t)
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, caPEM
}
