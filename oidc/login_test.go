package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// stubTok is an injectable TokenVerifier returning fixed claims.
type stubTok struct{ claims *Claims }

func (s stubTok) Verify(context.Context, string) (*Claims, error) { return s.claims, nil }

var testKey = bytes.Repeat([]byte{0x42}, 32)

func testAuth(t *testing.T, ver TokenVerifier, mut func(*AuthenticatorConfig)) *Authenticator {
	t.Helper()
	cfg := AuthenticatorConfig{
		Issuer: "https://idp.example.com", ClientID: "portal", RedirectURL: "https://app/auth/callback",
		Verifier: ver, SessionKey: testKey, CookiePrefix: "test_portal",
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mut != nil {
		mut(&cfg)
	}
	a, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

func TestNewAuthenticator_Validation(t *testing.T) {
	base := AuthenticatorConfig{Issuer: "i", ClientID: "c", RedirectURL: "r", Verifier: stubTok{}, SessionKey: testKey, CookiePrefix: "p"}
	for _, tc := range []struct {
		name string
		mut  func(*AuthenticatorConfig)
	}{
		{"issuer", func(c *AuthenticatorConfig) { c.Issuer = "" }},
		{"clientid", func(c *AuthenticatorConfig) { c.ClientID = "" }},
		{"redirect", func(c *AuthenticatorConfig) { c.RedirectURL = "" }},
		{"verifier", func(c *AuthenticatorConfig) { c.Verifier = nil }},
		{"key", func(c *AuthenticatorConfig) { c.SessionKey = nil }},
		{"prefix", func(c *AuthenticatorConfig) { c.CookiePrefix = "" }},
	} {
		cfg := base
		tc.mut(&cfg)
		if _, err := NewAuthenticator(cfg); err == nil {
			t.Errorf("%s: want validation error", tc.name)
		}
	}
}

func sessionCookieValue(t *testing.T, a *Authenticator, sess Session) string {
	t.Helper()
	v, err := a.seal(sess)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestGate_ExemptPathsPass(t *testing.T) {
	a := testAuth(t, stubTok{}, func(c *AuthenticatorConfig) { c.ExemptPaths = []string{"/healthz"} })
	h := a.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	for _, p := range []string{"/auth/login", "/auth/callback", "/auth/logout", "/healthz"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusTeapot {
			t.Errorf("%s: code = %d, want exempt passthrough", p, rec.Code)
		}
	}
}

func TestGate_UnauthenticatedGETRedirects(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	h := a.Gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next must not run") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/roles", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/auth/login?return_to=%2Froles" {
		t.Errorf("Location = %q", loc)
	}
}

func TestGate_UnauthenticatedNonGET401(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	h := a.Gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next must not run") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/roles", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

func TestGate_ValidSessionInjects(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	var got Session
	h := a.Gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := SessionFromContext(r.Context())
		if !ok {
			t.Error("session not injected")
		}
		got = s
		w.WriteHeader(http.StatusTeapot)
	}))
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(&http.Cookie{Name: a.sessionCookie, Value: sessionCookieValue(t, a, Session{Email: "a@x", Expiry: a.cfg.Now().Add(time.Hour)})})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot || got.Email != "a@x" {
		t.Fatalf("code=%d email=%q", rec.Code, got.Email)
	}
}

func TestGate_AdminGroupForbidden(t *testing.T) {
	a := testAuth(t, stubTok{}, func(c *AuthenticatorConfig) { c.AdminGroup = "admins" })
	h := a.Gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next must not run") }))
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(&http.Cookie{Name: a.sessionCookie, Value: sessionCookieValue(t, a, Session{Email: "a@x", Groups: []string{"eng"}, Expiry: a.cfg.Now().Add(time.Hour)})})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
}

func TestGate_ExpiredSessionRedirects(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	h := a.Gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next must not run") }))
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(&http.Cookie{Name: a.sessionCookie, Value: sessionCookieValue(t, a, Session{Email: "a@x", Expiry: a.cfg.Now().Add(-time.Minute)})})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expired session: code = %d, want 303 redirect", rec.Code)
	}
}

// startFlow runs LoginHandler and returns the sealed flow cookie + the decoded
// flow (state/nonce/verifier) so callback tests can craft a matching request.
func startFlow(t *testing.T, a *Authenticator) (*http.Cookie, oidcFlow) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.LoginHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/roles", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login code = %d, want 303", rec.Code)
	}
	var fc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == a.flowCookie {
			fc = c
		}
	}
	if fc == nil {
		t.Fatal("login set no flow cookie")
	}
	var flow oidcFlow
	if err := a.open(fc.Value, &flow); err != nil {
		t.Fatalf("open flow cookie: %v", err)
	}
	return fc, flow
}

func TestLogoutHandler_ClearsSessionAndRedirects(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	rec := httptest.NewRecorder()
	a.LogoutHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/auth/login" {
		t.Fatalf("logout: code=%d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == a.sessionCookie {
			sc = c
		}
	}
	if sc == nil || sc.MaxAge >= 0 {
		t.Errorf("logout should clear the session cookie (MaxAge < 0), got %+v", sc)
	}
}

func TestLoginCallback_RoundTrip(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	defer tokenSrv.Close()

	stub := stubTok{}
	a := testAuth(t, stub, func(c *AuthenticatorConfig) { c.Issuer = tokenSrv.URL })
	fc, flow := startFlow(t, a)

	// IdP would echo our nonce in the verified ID token.
	stub.claims = &Claims{Subject: "u-1", Email: "alice@x", Groups: []string{"admins"}, Nonce: flow.Nonce}
	a.cfg.Verifier = stub

	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(flow.State)+"&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback code = %d body=%q", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/roles" {
		t.Errorf("redirect = %q, want /roles (the captured return_to)", loc)
	}
	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == a.sessionCookie {
			sc = c
		}
	}
	if sc == nil {
		t.Fatal("callback set no session cookie")
	}
	var sess Session
	if err := a.open(sc.Value, &sess); err != nil {
		t.Fatalf("open session: %v", err)
	}
	if sess.Email != "alice@x" || len(sess.Groups) != 1 || sess.Groups[0] != "admins" {
		t.Errorf("session = %+v", sess)
	}
}

func TestCallback_StateMismatch(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	fc, _ := startFlow(t, a)
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state=WRONG&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "state mismatch") {
		t.Fatalf("code=%d body=%q, want 400 state mismatch", rec.Code, rec.Body.String())
	}
}

func TestCallback_NonceMismatch(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	defer tokenSrv.Close()
	stub := stubTok{claims: &Claims{Subject: "u", Nonce: "attacker-nonce"}} // != flow nonce
	a := testAuth(t, stub, func(c *AuthenticatorConfig) { c.Issuer = tokenSrv.URL })
	fc, flow := startFlow(t, a)
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(flow.State)+"&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "nonce mismatch") {
		t.Fatalf("code=%d body=%q, want 400 nonce mismatch", rec.Code, rec.Body.String())
	}
}
