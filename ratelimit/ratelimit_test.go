package ratelimit

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNew_DisabledWhenRPSNonPositive(t *testing.T) {
	if l := New(Config{RPS: 0}); l != nil {
		t.Error("RPS=0 should return nil (disabled)")
	}
	// nil limiter's Middleware must pass through.
	var nilLim *Limiter
	h := nilLim.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("nil limiter should pass through; got %d", rec.Code)
	}
}

func TestAllow_BurstThenThrottle(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 2, Log: discard()})
	now := time.Unix(0, 0)
	if !l.allow("1.2.3.4", now) {
		t.Fatal("first request within burst should be allowed")
	}
	if !l.allow("1.2.3.4", now) {
		t.Fatal("second request within burst should be allowed")
	}
	if l.allow("1.2.3.4", now) {
		t.Error("third immediate request should be throttled")
	}
	// A different source has its own bucket.
	if !l.allow("5.6.7.8", now) {
		t.Error("distinct source should not share the bucket")
	}
	// After a second, one token has refilled.
	if !l.allow("1.2.3.4", now.Add(time.Second)) {
		t.Error("token should refill after 1s at 1 rps")
	}
}

func TestKey_IgnoresXFFWithoutTrustedProxy(t *testing.T) {
	l := New(Config{RPS: 1})
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "203.0.113.9:4444"
	r.Header.Set("X-Forwarded-For", "1.1.1.1") // must be ignored — peer not trusted
	if got := l.key(r); got != "203.0.113.9" {
		t.Errorf("key = %q, want peer IP 203.0.113.9 (XFF ignored)", got)
	}
}

func TestKey_TrustedProxyUsesRightmostUntrustedHop(t *testing.T) {
	l := New(Config{RPS: 1, TrustedProxies: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}})
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "10.0.0.5:4444" // trusted proxy
	// Rightmost untrusted hop is the real client; 10.x hops are our own edge.
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.9, 10.0.0.5")
	if got := l.key(r); got != "198.51.100.7" {
		t.Errorf("key = %q, want 198.51.100.7 (rightmost untrusted hop)", got)
	}
}

func TestMiddleware_ExemptAnd429(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 1, Log: discard()})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := l.Middleware(next, "/healthz")

	// Exempt path always passes, even when the bucket would be empty.
	for range 3 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusTeapot {
			t.Fatalf("/healthz should be exempt; got %d", rec.Code)
		}
	}

	// First non-exempt request from a source is allowed (burst 1); second is 429.
	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		r.RemoteAddr = "203.0.113.1:5555"
		return r
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req())
	if rec.Code != http.StatusTeapot {
		t.Fatalf("first /api should pass; got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req())
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second /api should be 429; got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 should carry a Retry-After header")
	}
}

func TestMiddleware_OnThrottle(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 1, Log: discard(), OnThrottle: func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"slow down"}`))
	}})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := l.Middleware(next)

	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		r.RemoteAddr = "203.0.113.2:5555"
		return r
	}
	// Burst 1: first passes, second is throttled and rendered by OnThrottle.
	h.ServeHTTP(httptest.NewRecorder(), req())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req())

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("OnThrottle should set the status; got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if rec.Body.String() != `{"error":"slow down"}` {
		t.Errorf("body = %q", rec.Body.String())
	}
	// Retry-After is set before OnThrottle runs, so it's still present.
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After should be set even with a custom OnThrottle")
	}
}
