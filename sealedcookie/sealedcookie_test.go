package sealedcookie

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/clientip"
)

var testKey = bytes.Repeat([]byte{0x42}, 32)

type payload struct {
	A string `json:"a"`
	B int    `json:"b"`
}

func fixedNow() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

func TestSetReadClear_RoundTrip(t *testing.T) {
	c := Cookie{Key: testKey, Name: "app_cookie", Path: "/app", Now: fixedNow}

	rec := httptest.NewRecorder()
	if err := c.Set(rec, httptest.NewRequest(http.MethodGet, "/", nil), payload{A: "x", B: 1}, time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}
	var sc *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "app_cookie" {
			sc = ck
		}
	}
	if sc == nil {
		t.Fatal("Set wrote no cookie")
	}
	if sc.Path != "/app" || sc.SameSite != http.SameSiteLaxMode || !sc.HttpOnly {
		t.Errorf("cookie attrs = %+v", sc)
	}
	if want := int(time.Hour.Seconds()); sc.MaxAge != want {
		t.Errorf("MaxAge = %d, want %d", sc.MaxAge, want)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(sc)
	var got payload
	if err := c.Read(r, &got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != (payload{A: "x", B: 1}) {
		t.Errorf("Read = %+v", got)
	}
}

func TestRead_Errors(t *testing.T) {
	c := Cookie{Key: testKey, Name: "app_cookie", Path: "/", Now: fixedNow}
	var dst payload

	// Absent cookie.
	if err := c.Read(httptest.NewRequest(http.MethodGet, "/", nil), &dst); err == nil {
		t.Error("want error for missing cookie")
	}

	// Present but garbage value.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "app_cookie", Value: "not-a-sealed-value"})
	if err := c.Read(r, &dst); err == nil {
		t.Error("want error for malformed cookie value")
	}

	// Sealed under a DIFFERENT key.
	other := Cookie{Key: bytes.Repeat([]byte{0x24}, 32), Name: "app_cookie", Path: "/", Now: fixedNow}
	rec := httptest.NewRecorder()
	_ = other.Set(rec, httptest.NewRequest(http.MethodGet, "/", nil), payload{A: "x"}, time.Hour)
	var sc *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		sc = ck
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(sc)
	if err := c.Read(r2, &dst); err == nil {
		t.Error("want error for cookie sealed under a different key")
	}
}

func TestClear(t *testing.T) {
	c := Cookie{Key: testKey, Name: "app_cookie", Path: "/app", Now: fixedNow}
	rec := httptest.NewRecorder()
	c.Clear(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var sc *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "app_cookie" {
			sc = ck
		}
	}
	if sc == nil || sc.MaxAge >= 0 || sc.Path != "/app" {
		t.Errorf("Clear cookie = %+v", sc)
	}
}

func TestSealOpen_RoundTripAndTamper(t *testing.T) {
	sealed, err := Seal(testKey, payload{A: "x", B: 7})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var got payload
	if err := Open(testKey, sealed, &got); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != (payload{A: "x", B: 7}) {
		t.Errorf("Open = %+v", got)
	}
	if err := Open(testKey, sealed+"x", &got); err == nil {
		t.Error("want error for tampered sealed value")
	}
}

func TestIsHTTPS(t *testing.T) {
	isHTTPS := Cookie{}.isHTTPS // no Proxies: legacy behaviour
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	if isHTTPS(plain) {
		t.Error("plain request reported as HTTPS")
	}

	forwarded := httptest.NewRequest(http.MethodGet, "/", nil)
	forwarded.Header.Set("X-Forwarded-Proto", "https")
	if !isHTTPS(forwarded) {
		t.Error("want true behind a TLS-terminating proxy recording X-Forwarded-Proto: https")
	}

	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.TLS = &tls.ConnectionState{}
	if !isHTTPS(direct) {
		t.Error("want true for a direct TLS connection")
	}

	forwardedHTTP := httptest.NewRequest(http.MethodGet, "/", nil)
	forwardedHTTP.Header.Set("X-Forwarded-Proto", "http")
	if isHTTPS(forwardedHTTP) {
		t.Error("want false when the proxy explicitly recorded plain http")
	}
}

// TestSetClear_SecureReflectsIsHTTPS: Set/Clear thread isHTTPS through to
// the cookie's Secure attribute — including behind a TLS-terminating
// proxy where r.TLS alone would be nil.
func TestSetClear_SecureReflectsIsHTTPS(t *testing.T) {
	c := Cookie{Key: testKey, Name: "app_cookie", Path: "/", Now: fixedNow}

	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	if err := c.Set(rec, plain, payload{A: "x"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if rec.Result().Cookies()[0].Secure {
		t.Error("Set: Secure = true over plaintext with no forwarded-proto header")
	}

	behindProxy := httptest.NewRequest(http.MethodGet, "/", nil)
	behindProxy.Header.Set("X-Forwarded-Proto", "https")
	rec2 := httptest.NewRecorder()
	if err := c.Set(rec2, behindProxy, payload{A: "x"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !rec2.Result().Cookies()[0].Secure {
		t.Error("Set: Secure = false behind a TLS-terminating proxy (r.TLS nil, X-Forwarded-Proto: https)")
	}

	rec3 := httptest.NewRecorder()
	c.Clear(rec3, behindProxy)
	if !rec3.Result().Cookies()[0].Secure {
		t.Error("Clear: Secure = false behind a TLS-terminating proxy")
	}
}

// TestCookie_ZeroTTL_BrowserSessionCookie: ttl <= 0 omits Expires/Max-Age
// entirely (a browser-session cookie), rather than setting an
// immediately-expired Expires — the two are NOT the same thing.
func TestCookie_ZeroTTL_BrowserSessionCookie(t *testing.T) {
	c := Cookie{Key: testKey, Name: "app_cookie", Path: "/", Now: fixedNow}
	rec := httptest.NewRecorder()
	if err := c.Set(rec, httptest.NewRequest(http.MethodGet, "/", nil), payload{A: "x"}, 0); err != nil {
		t.Fatal(err)
	}
	sc := rec.Result().Cookies()[0]
	if sc.MaxAge != 0 {
		t.Errorf("MaxAge = %d, want 0 (omitted — browser-session cookie)", sc.MaxAge)
	}
	if !sc.Expires.IsZero() {
		t.Errorf("Expires = %v, want zero value (omitted)", sc.Expires)
	}
}

func TestCookie_SealIsBoundToName(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	a := Cookie{Key: key, Name: "app_session"}
	b := Cookie{Key: key, Name: "app_flow"}
	sealed, err := a.Seal(map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := a.Open(sealed, &got); err != nil || got["k"] != "v" {
		t.Fatalf("same-name open: %v %v", got, err)
	}
	if err := b.Open(sealed, &got); err == nil {
		t.Fatal("value sealed for one cookie name opened under another sharing the key")
	}
	// The name-less package-level Seal must not open as a named cookie either.
	plain, _ := Seal(key, map[string]string{"k": "v"})
	if err := a.Open(plain, &got); err == nil {
		t.Fatal("unbound value opened as a named cookie")
	}
}

func TestCookie_SecureFlagTrustsForwardedProtoPerProxies(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	withList := clientip.New([]*net.IPNet{trusted})

	tests := []struct {
		name    string
		proxies *clientip.Extractor
		remote  string
		xfp     string
		tls     bool
		want    bool
	}{
		{"legacy: no extractor honours XFP", nil, "203.0.113.9:1", "https", false, true},
		{"legacy: empty list honours XFP", clientip.New(nil), "203.0.113.9:1", "https", false, true},
		{"trusted peer XFP https", withList, "10.0.0.5:1", "https", false, true},
		{"untrusted peer cannot assert XFP", withList, "203.0.113.9:1", "https", false, false},
		{"trusted peer XFP http", withList, "10.0.0.5:1", "http", false, false},
		{"no XFP", withList, "10.0.0.5:1", "", false, false},
		{"direct TLS always secure", withList, "203.0.113.9:1", "", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Cookie{Key: testKey, Name: "c", Path: "/", Proxies: tt.proxies}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			if tt.xfp != "" {
				r.Header.Set("X-Forwarded-Proto", tt.xfp)
			}
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			w := httptest.NewRecorder()
			if err := c.Set(w, r, "v", time.Hour); err != nil {
				t.Fatal(err)
			}
			if got := w.Result().Cookies()[0].Secure; got != tt.want {
				t.Errorf("Set Secure = %v, want %v", got, tt.want)
			}
			w = httptest.NewRecorder()
			c.Clear(w, r)
			if got := w.Result().Cookies()[0].Secure; got != tt.want {
				t.Errorf("Clear Secure = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSet_RejectsOversizedValue(t *testing.T) {
	c := Cookie{Key: testKey, Name: "app_cookie", Path: "/", Now: fixedNow}
	rec := httptest.NewRecorder()
	err := c.Set(rec, httptest.NewRequest(http.MethodGet, "/", nil), payload{A: strings.Repeat("x", 4000)}, time.Hour)
	if err == nil {
		t.Fatal("expected error for a value over the browser cookie limit")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("no cookie should be written on error")
	}
}
