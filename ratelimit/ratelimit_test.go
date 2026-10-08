package ratelimit

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
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

// Keying logic itself lives in (and is tested by) the clientip package; this
// verifies TrustedProxies is wired through Middleware so the limiter keys on
// the real client behind a trusted proxy, not the shared proxy IP.
func TestMiddleware_KeysOnRealClientBehindTrustedProxy(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 1, Log: discard(), TrustedProxies: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := l.Middleware(next)

	send := func(xff string) int {
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		r.RemoteAddr = "10.0.0.5:5555" // trusted proxy
		r.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	// Two distinct real clients via the same proxy each get their own bucket.
	if got := send("198.51.100.7"); got != http.StatusTeapot {
		t.Fatalf("client A first request: got %d", got)
	}
	if got := send("203.0.113.8"); got != http.StatusTeapot {
		t.Fatalf("client B first request should pass (separate bucket): got %d", got)
	}
	// Second request from client A shares A's key and is throttled.
	if got := send("198.51.100.7"); got != http.StatusTooManyRequests {
		t.Fatalf("client A second request should be 429: got %d", got)
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

func TestMiddleware_IPv6RotationWithinPrefixSharesBucket(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 1, Log: discard()})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	send := func(remote string) int {
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		r.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if got := send("[2001:db8:1:2::1]:1000"); got != http.StatusTeapot {
		t.Fatalf("first request: got %d", got)
	}
	if got := send("[2001:db8:1:2::2]:1000"); got != http.StatusTooManyRequests {
		t.Errorf("rotated address in same /64 should share the bucket; got %d", got)
	}
	if got := send("[2001:db8:1:3::1]:1000"); got != http.StatusTeapot {
		t.Errorf("different /64 should have its own bucket; got %d", got)
	}
}

func TestAllow_BucketCapUsesSharedOverflow(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 1, Log: discard()})
	now := time.Unix(0, 0)
	for i := range maxBuckets {
		l.buckets[strconv.Itoa(i)] = &bucket{lim: rate.NewLimiter(1, 1), seen: now}
	}
	if !l.allow("new-a", now) {
		t.Fatal("first overflow request should be allowed")
	}
	if l.allow("new-b", now) {
		t.Error("overflow sources must share one bucket")
	}
	if len(l.buckets) != maxBuckets+1 {
		t.Errorf("buckets = %d, want %d (cap + overflow)", len(l.buckets), maxBuckets+1)
	}
}

// Throttle log lines are rate-limited per bucket so a client above its limit
// can't turn every rejected request into a log line.
func TestWarnDue_OncePerIntervalWithSuppressedCount(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 1, Log: discard()})
	now := time.Unix(1000, 0)
	l.allow("k", now)
	if due, n := l.warnDue("k", now); !due || n != 0 {
		t.Fatalf("first warn = (%v, %d), want (true, 0)", due, n)
	}
	for range 3 {
		if due, _ := l.warnDue("k", now.Add(time.Second)); due {
			t.Fatal("warn within the interval should be suppressed")
		}
	}
	if due, n := l.warnDue("k", now.Add(warnInterval)); !due || n != 3 {
		t.Fatalf("warn after interval = (%v, %d), want (true, 3)", due, n)
	}
}

func TestMiddleware_ThrottleLogIsSampled(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	l := New(Config{RPS: 1, Burst: 1, Log: log})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	for range 10 {
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		r.RemoteAddr = "203.0.113.9:1"
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if n := strings.Count(buf.String(), "rate limit exceeded"); n != 1 {
		t.Fatalf("logged %d throttle lines for 9 throttled requests, want 1:\n%s", n, buf.String())
	}
}

// A non-IP peer (unix socket) is never a trusted proxy: X-Forwarded-For is
// ignored and all such clients share one bucket.
func TestMiddleware_NonIPPeerSharesBucketAndIgnoresXFF(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 1, Log: discard(), TrustedProxies: []*net.IPNet{mustCIDR(t, "0.0.0.0/0")}})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	send := func(xff string) int {
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		r.RemoteAddr = "@"
		r.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if got := send("198.51.100.1"); got != http.StatusTeapot {
		t.Fatalf("first request: got %d", got)
	}
	if got := send("198.51.100.2"); got != http.StatusTooManyRequests {
		t.Errorf("different XFF behind a non-IP peer should still share the bucket; got %d", got)
	}
}
