package session

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/csrf"
	"github.com/abagile/tokyo3-base/sealedcookie"
)

var testKey = bytes.Repeat([]byte{0x42}, 32)

// clock is a mutable, advanceable clock for tests that need to observe
// behaviour across the passage of time (idle-extension thresholds).
type clock struct{ t time.Time }

func newClock() *clock                   { return &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }
func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func testManager(t *testing.T, mut func(*Config)) *Manager {
	t.Helper()
	cfg := Config{
		SessionKey: testKey, CookiePrefix: "test_portal",
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mut != nil {
		mut(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func sessionCookieValue(t *testing.T, m *Manager, sess Session) string {
	t.Helper()
	v, err := sealedcookie.Seal(m.cfg.SessionKey, sess)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNew_Validation(t *testing.T) {
	base := Config{SessionKey: testKey, CookiePrefix: "p"}
	for _, tc := range []struct {
		name string
		mut  func(*Config)
	}{
		{"key", func(c *Config) { c.SessionKey = nil }},
		{"prefix", func(c *Config) { c.CookiePrefix = "" }},
		{"basepath", func(c *Config) { c.BasePath = "portal" }}, // missing leading slash
	} {
		cfg := base
		tc.mut(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: want validation error", tc.name)
		}
	}
}

func TestGate_ExemptPathsPass(t *testing.T) {
	m := testManager(t, func(c *Config) { c.ExemptPaths = []string{"/healthz"} })
	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	for _, p := range []string{"/auth/login", "/auth/logout", "/healthz"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusTeapot {
			t.Errorf("%s: code = %d, want exempt passthrough", p, rec.Code)
		}
	}
}

func TestGate_UnauthenticatedGETRedirects(t *testing.T) {
	m := testManager(t, nil)
	h := m.Gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next must not run") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/roles", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/auth/login?return_to=%2Froles" {
		t.Errorf("Location = %q", loc)
	}
}

// TestBasePath_GateAndLogoutRedirects: when the handler tree is mounted
// under http.StripPrefix, route matching stays in the stripped space but
// every Location header must name the browser-visible URL — otherwise the
// login bounce 404s outside the mount (the certd /portal regression).
func TestBasePath_GateAndLogoutRedirects(t *testing.T) {
	m := testManager(t, func(c *Config) { c.BasePath = "/portal" })

	// Gate bounce: prefixed login path AND prefixed return_to.
	h := m.Gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next must not run") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/roles", nil))
	if loc := rec.Header().Get("Location"); loc != "/portal/auth/login?return_to=%2Fportal%2Froles" {
		t.Errorf("gate redirect = %q", loc)
	}

	// Gate still matches the login route in stripped space (no bounce loop).
	rec = httptest.NewRecorder()
	m.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("stripped login path: code = %d, want exempt passthrough", rec.Code)
	}

	// Logout: prefixed login path.
	rec = httptest.NewRecorder()
	m.LogoutHandler()(rec, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))
	if loc := rec.Header().Get("Location"); loc != "/portal/auth/login" {
		t.Errorf("logout redirect = %q", loc)
	}
}

// TestBasePath_SafeReturnToAndCookiePath covers the two small BasePath-aware
// helpers a login-flow implementation (base/oidc) leans on directly.
func TestBasePath_SafeReturnToAndCookiePath(t *testing.T) {
	m := testManager(t, func(c *Config) { c.BasePath = "/portal" })
	if got := m.SafeReturnTo(""); got != "/portal/" {
		t.Errorf(`SafeReturnTo("") = %q, want /portal/`, got)
	}
	if got := m.SafeReturnTo("//evil.example"); got != "/portal/" {
		t.Errorf("SafeReturnTo(unsafe) = %q, want /portal/ fallback", got)
	}
	if got := m.SafeReturnTo("/portal/roles"); got != "/portal/roles" {
		t.Errorf("SafeReturnTo(safe) = %q, want passthrough", got)
	}
	if got := m.CookiePath(); got != "/portal" {
		t.Errorf("CookiePath = %q, want /portal", got)
	}

	root := testManager(t, nil)
	if got := root.CookiePath(); got != "/" {
		t.Errorf("root mount CookiePath = %q, want /", got)
	}
}

func TestBasePath_TrailingSlashNormalised(t *testing.T) {
	m := testManager(t, func(c *Config) { c.BasePath = "/portal/" })
	if got := m.CookiePath(); got != "/portal" {
		t.Errorf("CookiePath = %q, want /portal (trailing slash trimmed)", got)
	}
}

// TestOriginCheck_DisabledByDefault: TrustedOrigins nil (the zero value)
// is opt-out — a cross-site POST (as a browser would mark it) still
// reaches the handler. Origin verification is defense-in-depth on top of
// the session-bound CSRF token, never a compulsory replacement.
func TestOriginCheck_DisabledByDefault(t *testing.T) {
	m := testManager(t, nil) // TrustedOrigins left nil
	var called bool
	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusTeapot) }))
	r := httptest.NewRequest(http.MethodPost, "/roles/new", nil)
	r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, Session{Email: "a@x", Expiry: m.cfg.Now().Add(time.Hour)})})
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if !called || rec.Code != http.StatusTeapot {
		t.Errorf("cross-site POST blocked despite TrustedOrigins == nil: code=%d called=%v", rec.Code, called)
	}
}

// TestOriginCheck_EnabledDeniesCrossSite: once opted in, a cross-site
// state-changing request is rejected before the handler runs, while a
// same-origin POST and any safe-method (GET) request still pass.
func TestOriginCheck_EnabledDeniesCrossSite(t *testing.T) {
	m := testManager(t, func(c *Config) { c.TrustedOrigins = &[]string{} })
	sessionCookie := &http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, Session{Email: "a@x", Expiry: m.cfg.Now().Add(time.Hour)})}

	var called bool
	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusTeapot) }))

	// Cross-site POST: denied, handler never runs.
	called = false
	r := httptest.NewRequest(http.MethodPost, "/roles/new", nil)
	r.AddCookie(sessionCookie)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden || called {
		t.Errorf("cross-site POST = %d called=%v, want 403 and no handler call", rec.Code, called)
	}

	// Same-origin POST: allowed through to the handler.
	called = false
	r = httptest.NewRequest(http.MethodPost, "/roles/new", nil)
	r.AddCookie(sessionCookie)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot || !called {
		t.Errorf("same-origin POST = %d called=%v, want 200-ish passthrough", rec.Code, called)
	}

	// Cross-site GET: safe method, always allowed regardless of origin.
	called = false
	r = httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(sessionCookie)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot || !called {
		t.Errorf("cross-site GET = %d called=%v, want passthrough (safe method)", rec.Code, called)
	}
}

// TestOriginCheck_TrustedOrigin: an origin added via TrustedOrigins is
// admitted even though it's cross-site.
func TestOriginCheck_TrustedOrigin(t *testing.T) {
	m := testManager(t, func(c *Config) {
		c.TrustedOrigins = &[]string{"https://sibling.example"}
	})
	var called bool
	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusTeapot) }))

	r := httptest.NewRequest(http.MethodPost, "/roles/new", nil)
	r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, Session{Email: "a@x", Expiry: m.cfg.Now().Add(time.Hour)})})
	r.Header.Set("Origin", "https://sibling.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot || !called {
		t.Errorf("trusted-origin POST = %d called=%v, want passthrough", rec.Code, called)
	}
}

// TestOriginCheck_EmptyVsNilInnerSlice: *TrustedOrigins == nil (a pointer
// to a nil slice) and *TrustedOrigins == []string{} (a pointer to an
// empty-but-non-nil slice) are the same state — enabled, no additional
// origins — since only the outer pointer's nilness switches the feature.
func TestOriginCheck_EmptyVsNilInnerSlice(t *testing.T) {
	var nilSlice []string     // nil
	nilInner := &nilSlice     // non-nil pointer to a nil slice
	emptyInner := &[]string{} // non-nil pointer to an empty (non-nil) slice
	for _, origins := range []*[]string{nilInner, emptyInner} {
		m := testManager(t, func(c *Config) { c.TrustedOrigins = origins })
		h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
		r := httptest.NewRequest(http.MethodPost, "/roles/new", nil)
		r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, Session{Email: "a@x", Expiry: m.cfg.Now().Add(time.Hour)})})
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("origins=%v: cross-site POST = %d, want 403 (feature enabled either way)", origins, rec.Code)
		}
	}
}

// TestOriginCheck_InvalidTrustedOrigin: a malformed entry fails
// construction rather than being silently ignored.
func TestOriginCheck_InvalidTrustedOrigin(t *testing.T) {
	cfg := Config{
		SessionKey: testKey, CookiePrefix: "p",
		TrustedOrigins: &[]string{"not a valid origin"},
	}
	if _, err := New(cfg); err == nil {
		t.Error("want error for a malformed TrustedOrigins entry")
	}
}

func TestGate_UnauthenticatedNonGET401(t *testing.T) {
	m := testManager(t, nil)
	h := m.Gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next must not run") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/roles", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

func TestGate_ValidSessionInjects(t *testing.T) {
	m := testManager(t, nil)
	var got Session
	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := SessionFromContext(r.Context())
		if !ok {
			t.Error("session not injected")
		}
		got = s
		w.WriteHeader(http.StatusTeapot)
	}))
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, Session{Email: "a@x", Expiry: m.cfg.Now().Add(time.Hour)})})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot || got.Email != "a@x" {
		t.Fatalf("code=%d email=%q", rec.Code, got.Email)
	}
}

func TestGate_RequiredGroupForbidden(t *testing.T) {
	m := testManager(t, func(c *Config) { c.RequiredGroup = "admins" })
	h := m.Gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next must not run") }))
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, Session{Email: "a@x", Groups: []string{"eng"}, Expiry: m.cfg.Now().Add(time.Hour)})})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
}

func TestGate_ExpiredSessionRedirects(t *testing.T) {
	m := testManager(t, nil)
	h := m.Gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next must not run") }))
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, Session{Email: "a@x", Expiry: m.cfg.Now().Add(-time.Minute)})})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expired session: code = %d, want 303 redirect", rec.Code)
	}
}

// TestUpdateSession: a gated handler mutates Session.Extra mid-session; the
// re-sealed cookie carries the change, Expiry is preserved (an update is not
// a renewal), and the cookie's remaining lifetime matches that expiry.
func TestUpdateSession(t *testing.T) {
	m := testManager(t, nil)
	expiry := m.cfg.Now().Add(2 * time.Hour)
	r := httptest.NewRequest(http.MethodPost, "/tenant", nil)
	r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, Session{Email: "a@x", Expiry: expiry})})
	rec := httptest.NewRecorder()

	err := m.UpdateSession(rec, r, func(s *Session) error {
		s.Extra = json.RawMessage(`{"tenant":"acme"}`)
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}

	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.cookie.Name {
			sc = c
		}
	}
	if sc == nil {
		t.Fatal("no re-sealed session cookie written")
	}
	var sess Session
	if err := sealedcookie.Open(m.cfg.SessionKey, sc.Value, &sess); err != nil {
		t.Fatalf("open updated session: %v", err)
	}
	if string(sess.Extra) != `{"tenant":"acme"}` || sess.Email != "a@x" {
		t.Errorf("updated session = %+v", sess)
	}
	if !sess.Expiry.Equal(expiry) {
		t.Errorf("Expiry = %v, want preserved %v", sess.Expiry, expiry)
	}
	if want := int((2 * time.Hour).Seconds()); sc.MaxAge != want {
		t.Errorf("cookie MaxAge = %d, want %d (remaining validity, not a renewal)", sc.MaxAge, want)
	}
}

func TestUpdateSession_Errors(t *testing.T) {
	m := testManager(t, nil)

	// No session cookie ⇒ error, nothing written.
	rec := httptest.NewRecorder()
	if err := m.UpdateSession(rec, httptest.NewRequest(http.MethodPost, "/tenant", nil), func(*Session) error { return nil }); err == nil {
		t.Error("want error without a valid session")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("cookie written despite missing session")
	}

	// Mutation failure ⇒ error surfaces, nothing written.
	r := httptest.NewRequest(http.MethodPost, "/tenant", nil)
	r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, Session{Email: "a@x", Expiry: m.cfg.Now().Add(time.Hour)})})
	rec = httptest.NewRecorder()
	if err := m.UpdateSession(rec, r, func(*Session) error { return context.DeadlineExceeded }); err == nil {
		t.Error("want mutation error surfaced")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("cookie written despite mutation failure")
	}
}

func TestLogoutHandler_ClearsSessionAndRedirects(t *testing.T) {
	m := testManager(t, nil)
	rec := httptest.NewRecorder()
	m.LogoutHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/auth/login" {
		t.Fatalf("logout: code=%d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.cookie.Name {
			sc = c
		}
	}
	if sc == nil || sc.MaxAge >= 0 {
		t.Errorf("logout should clear the session cookie (MaxAge < 0), got %+v", sc)
	}
}

// TestCSRFTokenValidate: session-bound tokens round-trip; scope partitions
// them; tampered tokens, foreign sessions, and missing sessions all fail.
func TestCSRFTokenValidate(t *testing.T) {
	m := testManager(t, nil)
	newReq := func(secret csrf.Secret) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/roles", nil)
		r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, Session{
			Email: "a@x", Expiry: m.cfg.Now().Add(time.Hour), CSRFSecret: secret,
		})})
		return r
	}
	r := newReq("secret-1")

	tok, err := m.CSRFToken(r, "roles/new")
	if err != nil || tok == "" {
		t.Fatalf("CSRFToken: %q, %v", tok, err)
	}
	if !m.ValidateCSRF(r, tok, "roles/new") {
		t.Error("valid token rejected")
	}

	// Masking: every render yields different wire bytes (no static secret
	// repeats across response bodies — BREACH defense), yet each issued
	// token stays independently valid (multi-tab keeps working).
	tok2, err := m.CSRFToken(r, "roles/new")
	if err != nil {
		t.Fatalf("second CSRFToken: %v", err)
	}
	if tok2 == tok {
		t.Error("wire token identical across renders — masking inactive")
	}
	if !m.ValidateCSRF(r, tok2, "roles/new") || !m.ValidateCSRF(r, tok, "roles/new") {
		t.Error("both issued tokens must remain valid")
	}
	if m.ValidateCSRF(r, tok, "revocations") {
		t.Error("token accepted for a different scope")
	}
	if m.ValidateCSRF(r, tok+"x", "roles/new") {
		t.Error("tampered token accepted")
	}
	if m.ValidateCSRF(r, "", "roles/new") {
		t.Error("empty token accepted")
	}
	if m.ValidateCSRF(newReq("secret-2"), tok, "roles/new") {
		t.Error("token from another session's secret accepted")
	}
	if _, err := m.CSRFToken(httptest.NewRequest(http.MethodGet, "/roles", nil), "x"); err == nil {
		t.Error("want error without a session")
	}

	// Rotating the secret via UpdateSession invalidates issued tokens.
	rec := httptest.NewRecorder()
	if err := m.UpdateSession(rec, r, func(s *Session) error {
		s.CSRFSecret = "rotated"
		return nil
	}); err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}
	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.cookie.Name {
			sc = c
		}
	}
	r2 := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r2.AddCookie(sc)
	if m.ValidateCSRF(r2, tok, "roles/new") {
		t.Error("pre-rotation token still accepted")
	}
}

// TestNewSessionAndIssueSession: NewSession mints Expiry+CSRFSecret; after
// the caller populates identity fields, IssueSession seals it into a
// cookie a subsequent Gate call reads back correctly.
func TestNewSessionAndIssueSession(t *testing.T) {
	m := testManager(t, nil)
	sess, err := m.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if sess.CSRFSecret == "" {
		t.Error("NewSession minted no CSRF secret")
	}
	wantExpiry := m.cfg.Now().Add(defaultSessionTTL)
	if !sess.Expiry.Equal(wantExpiry) {
		t.Errorf("Expiry = %v, want %v", sess.Expiry, wantExpiry)
	}
	sess.Email = "alice@x"
	sess.Groups = []string{"admins"}

	rec := httptest.NewRecorder()
	if err := m.IssueSession(rec, httptest.NewRequest(http.MethodGet, "/", nil), sess); err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.cookie.Name {
			sc = c
		}
	}
	if sc == nil {
		t.Fatal("IssueSession set no session cookie")
	}

	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SessionFromContext(r.Context())
		if s.Email != "alice@x" {
			t.Errorf("gated session email = %q", s.Email)
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(sc)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, r)
	if rec2.Code != http.StatusTeapot {
		t.Fatalf("gated request after IssueSession: code = %d", rec2.Code)
	}
}

// TestSiblingCookie: a caller's own related cookie (e.g. an OIDC
// login-flow state) shares this Manager's key, path scope, and clock, but
// gets its own name — proving it's usable as a fully independent cookie
// while staying tied to the same underlying config.
func TestSiblingCookie(t *testing.T) {
	m := testManager(t, func(c *Config) { c.BasePath = "/portal" })
	sib := m.SiblingCookie("flow")
	if sib.Name != "test_portal_flow" {
		t.Errorf("Name = %q, want test_portal_flow", sib.Name)
	}
	if sib.Path != "/portal" {
		t.Errorf("Path = %q, want /portal (matches CookiePath)", sib.Path)
	}
	if string(sib.Key) != string(m.cfg.SessionKey) {
		t.Error("Key does not match the Manager's SessionKey")
	}

	// Round-trips independently of the session cookie.
	rec := httptest.NewRecorder()
	type flowState struct {
		Nonce string `json:"nonce"`
	}
	if err := sib.Set(rec, httptest.NewRequest(http.MethodGet, "/", nil), flowState{Nonce: "abc"}, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "test_portal_flow" {
			sc = c
		}
	}
	if sc == nil {
		t.Fatal("SiblingCookie.Set wrote no cookie")
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(sc)
	var got flowState
	if err := sib.Read(r, &got); err != nil || got.Nonce != "abc" {
		t.Fatalf("Read = %+v, %v", got, err)
	}
}

func TestLog(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := testManager(t, func(c *Config) { c.Log = log })
	if m.Log() != log {
		t.Error("Log() did not return the configured logger")
	}
	// Default (nil Config.Log) still returns a usable, non-nil logger.
	m2 := testManager(t, func(c *Config) { c.Log = nil })
	if m2.Log() == nil {
		t.Error("Log() returned nil when Config.Log was unset")
	}
}

func TestNewSession_IdleTimeoutDisabled_ExpiryEqualsAbsolute(t *testing.T) {
	m := testManager(t, func(c *Config) { c.SessionTTL = 2 * time.Hour }) // IdleTimeout left 0
	sess, err := m.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if !sess.Expiry.Equal(sess.AbsoluteExpiry) {
		t.Errorf("Expiry = %v, AbsoluteExpiry = %v, want equal (hard-cap-only default)", sess.Expiry, sess.AbsoluteExpiry)
	}
}

func TestNewSession_IdleTimeoutEnabled_StartsWithinIdleWindow(t *testing.T) {
	clk := newClock()
	m := testManager(t, func(c *Config) {
		c.SessionTTL = 2 * time.Hour
		c.IdleTimeout = 30 * time.Minute
		c.Now = clk.now
	})
	sess, err := m.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if want := clk.now().Add(30 * time.Minute); !sess.Expiry.Equal(want) {
		t.Errorf("Expiry = %v, want %v (idle window, not the full absolute ceiling)", sess.Expiry, want)
	}
	if want := clk.now().Add(2 * time.Hour); !sess.AbsoluteExpiry.Equal(want) {
		t.Errorf("AbsoluteExpiry = %v, want %v", sess.AbsoluteExpiry, want)
	}
}

// TestGate_IdleExtend_NoOpWithinFirstHalfOfWindow: fewer than half the idle
// window has elapsed since issuance — Gate must not re-seal the cookie on
// every single request.
func TestGate_IdleExtend_NoOpWithinFirstHalfOfWindow(t *testing.T) {
	clk := newClock()
	m := testManager(t, func(c *Config) {
		c.SessionTTL = 2 * time.Hour
		c.IdleTimeout = 30 * time.Minute
		c.Now = clk.now
	})
	sess, _ := m.NewSession()
	sess.Email = "a@x"
	rec0 := httptest.NewRecorder()
	if err := m.IssueSession(rec0, httptest.NewRequest(http.MethodGet, "/", nil), sess); err != nil {
		t.Fatal(err)
	}
	var sc *http.Cookie
	for _, c := range rec0.Result().Cookies() {
		if c.Name == m.cookie.Name {
			sc = c
		}
	}

	clk.advance(10 * time.Minute) // < half of the 30m idle window
	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(sc)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("code = %d", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("Gate re-sealed the cookie despite being within the first half of the idle window")
	}
}

// TestGate_IdleExtend_ExtendsPastHalfWindow: more than half the idle window
// has elapsed — Gate re-seals with a pushed-out Expiry, and the new cookie
// keeps working on a subsequent request.
func TestGate_IdleExtend_ExtendsPastHalfWindow(t *testing.T) {
	clk := newClock()
	m := testManager(t, func(c *Config) {
		c.SessionTTL = 2 * time.Hour
		c.IdleTimeout = 30 * time.Minute
		c.Now = clk.now
	})
	sess, _ := m.NewSession()
	sess.Email = "a@x"
	rec0 := httptest.NewRecorder()
	_ = m.IssueSession(rec0, httptest.NewRequest(http.MethodGet, "/", nil), sess)
	var sc *http.Cookie
	for _, c := range rec0.Result().Cookies() {
		if c.Name == m.cookie.Name {
			sc = c
		}
	}

	clk.advance(20 * time.Minute) // > half of the 30m idle window
	var gotEmail string
	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SessionFromContext(r.Context())
		gotEmail = s.Email
		w.WriteHeader(http.StatusTeapot)
	}))
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(sc)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot || gotEmail != "a@x" {
		t.Fatalf("code=%d email=%q", rec.Code, gotEmail)
	}
	var extended *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.cookie.Name {
			extended = c
		}
	}
	if extended == nil {
		t.Fatal("Gate did not re-seal the cookie past the halfway threshold")
	}

	// The extended cookie keeps working on a later request.
	clk.advance(5 * time.Minute)
	rec2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r2.AddCookie(extended)
	h.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusTeapot {
		t.Fatalf("extended cookie rejected: code = %d", rec2.Code)
	}
}

// TestGate_IdleExtend_CappedAtAbsoluteExpiry: idle extension never pushes
// Expiry past AbsoluteExpiry, even when the full idle window would.
func TestGate_IdleExtend_CappedAtAbsoluteExpiry(t *testing.T) {
	clk := newClock()
	m := testManager(t, func(c *Config) {
		c.SessionTTL = 30 * time.Minute // absolute cap is close
		c.IdleTimeout = 20 * time.Minute
		c.Now = clk.now
	})
	sess, _ := m.NewSession() // Expiry = now+20m, AbsoluteExpiry = now+30m
	rec0 := httptest.NewRecorder()
	_ = m.IssueSession(rec0, httptest.NewRequest(http.MethodGet, "/", nil), sess)
	var sc *http.Cookie
	for _, c := range rec0.Result().Cookies() {
		if c.Name == m.cookie.Name {
			sc = c
		}
	}

	clk.advance(15 * time.Minute) // > half of 20m idle window; naive extension would be now+20m = mint+35m > AbsoluteExpiry(mint+30m)
	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(sc)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("code = %d", rec.Code)
	}
	var extended *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.cookie.Name {
			extended = c
		}
	}
	if extended == nil {
		t.Fatal("expected an extension attempt (capped, not skipped)")
	}
	var got Session
	if err := sealedcookie.Open(m.cfg.SessionKey, extended.Value, &got); err != nil {
		t.Fatalf("open extended cookie: %v", err)
	}
	if !got.Expiry.Equal(sess.AbsoluteExpiry) {
		t.Errorf("extended Expiry = %v, want capped at AbsoluteExpiry %v", got.Expiry, sess.AbsoluteExpiry)
	}
}

// TestGate_IdleExtend_Disabled_NeverReseals: the default (IdleTimeout == 0)
// never re-seals the cookie, matching pre-idle-extension behaviour exactly.
func TestGate_IdleExtend_Disabled_NeverReseals(t *testing.T) {
	clk := newClock()
	m := testManager(t, func(c *Config) {
		c.SessionTTL = 30 * time.Minute
		c.Now = clk.now
	}) // IdleTimeout left at 0
	sess, _ := m.NewSession()
	rec0 := httptest.NewRecorder()
	_ = m.IssueSession(rec0, httptest.NewRequest(http.MethodGet, "/", nil), sess)
	var sc *http.Cookie
	for _, c := range rec0.Result().Cookies() {
		if c.Name == m.cookie.Name {
			sc = c
		}
	}

	clk.advance(29 * time.Minute) // still valid, well past any "half window" heuristic
	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(sc)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("code = %d", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("Gate re-sealed the cookie despite IdleTimeout being disabled")
	}
}
