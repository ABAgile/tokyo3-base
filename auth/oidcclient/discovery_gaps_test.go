package oidcclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A discovery document that redirects forever is abandoned after a bounded
// number of hops, and the convention endpoints are used instead.
func TestDiscoverEndpoints_RedirectLoopFallsBackToConvention(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()

	start := time.Now()
	if got := discoverEndpoints(context.Background(), srv.URL); got != conventionEndpoints(srv.URL) {
		t.Errorf("endpoints = %+v, want the convention fallback", got)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("discovery took %v; the redirect loop should end after a few hops", elapsed)
	}
}

// An issuer that is not a valid request URL is never contacted, and the
// convention endpoints are used.
func TestDiscoverEndpoints_MalformedIssuerFallsBack(t *testing.T) {
	const issuer = "http://[::1"
	if got := discoverEndpoints(context.Background(), issuer); got != conventionEndpoints(issuer) {
		t.Errorf("endpoints = %+v, want the convention fallback", got)
	}
}

// A discovery response cut off mid-body is not a usable document, so the
// convention endpoints are used.
func TestDiscoverEndpoints_TruncatedDocumentFallsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("response writer cannot hijack")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		// The header promises 500 bytes; the body stops after a few, and the
		// connection closes.
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\nConnection: close\r\n\r\n{\"issuer\":")
		_ = buf.Flush()
	}))
	defer srv.Close()

	if got := discoverEndpoints(context.Background(), srv.URL); got != conventionEndpoints(srv.URL) {
		t.Errorf("endpoints = %+v, want the convention fallback", got)
	}
}
