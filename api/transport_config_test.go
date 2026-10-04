package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v2"
)

// TestRestyClient_TLSConfiguredThroughOptions: Resty setters applied as
// constructor options run before the error-body limiter wraps the transport,
// so TLS/root-CA settings take effect and the limiter wraps the result.
func TestRestyClient_TLSConfiguredThroughOptions(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	rc := NewRestClient(srv.URL, func(c *resty.Client) {
		c.SetTLSClientConfig(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
	})
	if _, ok := rc.GetClient().Transport.(errorBodyTransport); !ok {
		t.Fatal("transport is not wrapped by the error-body limiter")
	}
	var out struct{ OK bool }
	if err := rc.R(context.Background(), "GET", "/", &out); err != nil || !out.OK {
		t.Fatalf("TLS request via option-configured client: out=%v err=%v", out, err)
	}
	rc.GetClient().CloseIdleConnections()
}

// TestRestyClient_TransportSettersAfterConstructionAreUnsupported pins the
// documented limitation: Resty's transport setters need a bare *http.Transport,
// so once the limiter wraps it they are ignored rather than mutating anything.
func TestRestyClient_TransportSettersAfterConstructionAreUnsupported(t *testing.T) {
	rc := NewRestClient("http://example.test")
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	rc.SetTLSClientConfig(cfg)
	wrapped, ok := rc.GetClient().Transport.(errorBodyTransport)
	if !ok {
		t.Fatal("transport is not wrapped by the error-body limiter")
	}
	if base, ok := wrapped.base.(*http.Transport); ok && base.TLSClientConfig == cfg {
		t.Fatal("post-construction setter unexpectedly reached the transport; update the README")
	}
}
