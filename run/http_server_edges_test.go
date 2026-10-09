package run_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/run"
)

func freeListenAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// selfSigned returns a loopback certificate, plus a pool that trusts it.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "run-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// With useTLS set the component must serve HTTPS. A plain-HTTP request would
// fail, so a 200 over TLS proves the TLS listener is the one running.
func TestHTTPServer_TLSServesHTTPS(t *testing.T) {
	cert, pool := selfSigned(t)
	addr := freeListenAddr(t)
	srv := &http.Server{
		Addr:      addr,
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("tls-ok")) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- run.HTTPServer(srv, time.Second, true)(ctx) }()

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}},
	}
	var resp *http.Response
	var err error
	for range 100 {
		resp, err = client.Get("https://" + addr + "/")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("HTTPS GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "tls-ok" {
		t.Errorf("HTTPS response = %d %q, want 200 tls-ok", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("graceful TLS shutdown = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TLS server did not stop after cancel")
	}
}

// A TLS server with no certificate must fail to start and report why, rather
// than silently serve plaintext or hang.
func TestHTTPServer_TLSWithoutCertificateReturnsError(t *testing.T) {
	srv := &http.Server{Addr: freeListenAddr(t), Handler: http.NewServeMux()}
	err := run.HTTPServer(srv, time.Second, true)(t.Context())
	if err == nil {
		t.Fatal("TLS server without a certificate returned nil")
	}
}

// If someone else closes the server, the component must report that as a clean
// stop (nil), not as a failure, since nothing went wrong.
func TestHTTPServer_ExternalCloseReturnsNil(t *testing.T) {
	addr := freeListenAddr(t)
	srv := &http.Server{Addr: addr, Handler: http.NewServeMux()}
	done := make(chan error, 1)
	go func() { done <- run.HTTPServer(srv, time.Second, false)(t.Context()) }()

	for range 100 {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("srv.Close: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("component after external Close = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("component did not return after external Close")
	}
}
