package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/sealedcookie"
	"github.com/abagile/tokyo3-base/session"
)

// stubTok is an injectable TokenVerifier returning fixed claims.
type stubTok struct{ claims *Claims }

func (s stubTok) Verify(context.Context, string) (*Claims, error) { return s.claims, nil }

var testKey = bytes.Repeat([]byte{0x42}, 32)

// testSessionManager builds the session.Manager an Authenticator is
// injected with — mirrors what a real caller (e.g. ca's portal.New) builds
// independently and passes to [NewAuthenticator]. ExemptPaths always
// includes the default callback route so testAuth's default CallbackPath
// passes NewAuthenticator's exemption check.
func testSessionManager(t *testing.T, mut func(*session.Config)) *session.Manager {
	t.Helper()
	cfg := session.Config{
		SessionKey: testKey, CookiePrefix: "test_portal",
		ExemptPaths: []string{defaultCallbackPath},
		Now:         func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mut != nil {
		mut(&cfg)
	}
	m, err := session.New(cfg)
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	return m
}

func testAuth(t *testing.T, ver TokenVerifier, mut func(*AuthenticatorConfig)) *Authenticator {
	t.Helper()
	return testAuthWith(t, ver, mut, testSessionManager(t, nil))
}

// testAuthWith is testAuth with an explicit session.Manager, for tests that
// need to control the Manager's own config (e.g. BasePath).
func testAuthWith(t *testing.T, ver TokenVerifier, mut func(*AuthenticatorConfig), sess *session.Manager) *Authenticator {
	t.Helper()
	cfg := AuthenticatorConfig{
		Issuer: "https://idp.example.com", ClientID: "portal", RedirectURL: "https://app/auth/callback",
		Verifier:   ver,
		FlowCookie: sess.SiblingCookie("flow"),
	}
	if mut != nil {
		mut(&cfg)
	}
	a, err := NewAuthenticator(cfg, sess)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

// otherCookie returns the first cookie in cookies whose name isn't
// exclude — used to find the session cookie a callback set without
// reproducing session.Manager's internal naming convention in test code
// (the only two cookies in play here are the flow cookie and, once
// issued, the session cookie).
func otherCookie(cookies []*http.Cookie, exclude string) *http.Cookie {
	for _, c := range cookies {
		if c.Name != exclude {
			return c
		}
	}
	return nil
}

func TestNewAuthenticator_Validation(t *testing.T) {
	validSess := testSessionManager(t, nil)
	base := AuthenticatorConfig{
		Issuer: "i", ClientID: "c", RedirectURL: "r", Verifier: stubTok{},
		FlowCookie: validSess.SiblingCookie("flow"),
	}
	for _, tc := range []struct {
		name string
		mut  func(*AuthenticatorConfig)
		sess *session.Manager
	}{
		{"issuer", func(c *AuthenticatorConfig) { c.Issuer = "" }, validSess},
		{"clientid", func(c *AuthenticatorConfig) { c.ClientID = "" }, validSess},
		{"redirect", func(c *AuthenticatorConfig) { c.RedirectURL = "" }, validSess},
		{"verifier", func(c *AuthenticatorConfig) { c.Verifier = nil }, validSess},
		{"flow cookie", func(c *AuthenticatorConfig) { c.FlowCookie = sealedcookie.Cookie{} }, validSess},
		{"nil session manager", func(*AuthenticatorConfig) {}, nil},
	} {
		cfg := base
		tc.mut(&cfg)
		if _, err := NewAuthenticator(cfg, tc.sess); err == nil {
			t.Errorf("%s: want validation error", tc.name)
		}
	}
}

// TestNewAuthenticator_RequiresCallbackPathExempt: construction fails when
// the injected session.Manager doesn't exempt CallbackPath from its Gate —
// otherwise the OIDC callback would be redirected to login before the flow
// could ever complete.
func TestNewAuthenticator_RequiresCallbackPathExempt(t *testing.T) {
	sess := testSessionManager(t, func(c *session.Config) { c.ExemptPaths = nil }) // no /auth/callback exemption
	cfg := AuthenticatorConfig{
		Issuer: "i", ClientID: "c", RedirectURL: "r", Verifier: stubTok{},
		FlowCookie: sess.SiblingCookie("flow"),
	}
	if _, err := NewAuthenticator(cfg, sess); err == nil {
		t.Error("want error when the session.Manager doesn't exempt CallbackPath")
	}
}

// TestLoginHandler_ReturnToAndCookieScope: the login-flow cookie shares
// BasePath-derived scoping and return_to sanitisation with the session
// cookie — both come from the same injected session.Manager.
func TestLoginHandler_ReturnToAndCookieScope(t *testing.T) {
	sess := testSessionManager(t, func(c *session.Config) { c.BasePath = "/portal" })
	a := testAuthWith(t, stubTok{}, nil, sess)

	rec := httptest.NewRecorder()
	a.LoginHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	var fc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == a.flow.Name {
			fc = c
		}
	}
	if fc == nil {
		t.Fatal("login set no flow cookie")
	}
	var flow oidcFlow
	if err := sealedcookie.Open(a.flow.Key, fc.Value, &flow); err != nil {
		t.Fatalf("open flow cookie: %v", err)
	}
	if flow.ReturnTo != "/portal/" {
		t.Errorf("fallback return_to = %q, want /portal/ (no return_to given)", flow.ReturnTo)
	}
	if fc.Path != "/portal" {
		t.Errorf("flow cookie path = %q, want /portal (shares the session cookie's scope)", fc.Path)
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
		if c.Name == a.flow.Name {
			fc = c
		}
	}
	if fc == nil {
		t.Fatal("login set no flow cookie")
	}
	var flow oidcFlow
	if err := sealedcookie.Open(a.flow.Key, fc.Value, &flow); err != nil {
		t.Fatalf("open flow cookie: %v", err)
	}
	return fc, flow
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
	sc := otherCookie(rec.Result().Cookies(), a.flow.Name)
	if sc == nil {
		t.Fatal("callback set no session cookie")
	}
	var sess session.Session
	if err := sealedcookie.Open(a.flow.Key, sc.Value, &sess); err != nil {
		t.Fatalf("open session: %v", err)
	}
	if sess.Email != "alice@x" || len(sess.Groups) != 1 || sess.Groups[0] != "admins" {
		t.Errorf("session = %+v", sess)
	}
	if sess.CSRFSecret == "" {
		t.Error("callback minted no CSRF secret")
	}
}

// TestCallback_EnrichSession: a consumer hook populates Session.Extra with
// its own typed payload at login; the payload round-trips through the sealed
// cookie and comes back verbatim on session read.
func TestCallback_EnrichSession(t *testing.T) {
	type appData struct {
		Tenant string `json:"tenant"`
		Beta   bool   `json:"beta"`
	}
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	defer tokenSrv.Close()

	stub := stubTok{}
	a := testAuth(t, stub, func(c *AuthenticatorConfig) {
		c.Issuer = tokenSrv.URL
		c.EnrichSession = func(_ context.Context, claims *Claims, sess *session.Session) error {
			b, err := json.Marshal(appData{Tenant: "acme-" + claims.Subject, Beta: true})
			if err != nil {
				return err
			}
			sess.Extra = b
			return nil
		}
	})
	fc, flow := startFlow(t, a)
	stub.claims = &Claims{Subject: "u-1", Email: "alice@x", Nonce: flow.Nonce}
	a.cfg.Verifier = stub

	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(flow.State)+"&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback code = %d body=%q", rec.Code, rec.Body.String())
	}

	sc := otherCookie(rec.Result().Cookies(), a.flow.Name)
	if sc == nil {
		t.Fatal("callback set no session cookie")
	}
	var sess session.Session
	if err := sealedcookie.Open(a.flow.Key, sc.Value, &sess); err != nil {
		t.Fatalf("open session: %v", err)
	}
	var got appData
	if err := json.Unmarshal(sess.Extra, &got); err != nil {
		t.Fatalf("unmarshal Extra: %v", err)
	}
	if got.Tenant != "acme-u-1" || !got.Beta {
		t.Errorf("Extra = %+v", got)
	}
}

// TestCallback_EnrichSessionError: enrichment failure aborts the login — no
// session cookie is set (fail closed, never a session missing authz data).
func TestCallback_EnrichSessionError(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	defer tokenSrv.Close()

	stub := stubTok{}
	a := testAuth(t, stub, func(c *AuthenticatorConfig) {
		c.Issuer = tokenSrv.URL
		c.EnrichSession = func(context.Context, *Claims, *session.Session) error {
			return context.DeadlineExceeded // any enrichment failure
		}
	})
	fc, flow := startFlow(t, a)
	stub.claims = &Claims{Subject: "u-1", Nonce: flow.Nonce}
	a.cfg.Verifier = stub

	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(flow.State)+"&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("callback code = %d, want 500", rec.Code)
	}
	if sc := otherCookie(rec.Result().Cookies(), a.flow.Name); sc != nil {
		t.Fatalf("session cookie set despite enrichment failure: %+v", sc)
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

// ── CompletionOverride ────────────────────────────────────────────────────────

// fakeOverrideIssuer is a minimal SessionIssuer + CompletionOverride
// implementation exercising the full-response-control completion path —
// mirroring how a token-table-backed caller (e.g. vault) would plug in
// without any session.Manager cookie at all. Deliberately does NOT
// implement DefaultCompleter, to prove CompletionOverride alone suffices.
type fakeOverrideIssuer struct {
	callbackPath string
	completeErr  error

	gotClaims *Claims
	gotFlow   CompletedFlow
	called    bool
}

func (f *fakeOverrideIssuer) SafeReturnTo(string) string { return "/fallback" }
func (f *fakeOverrideIssuer) IsExempt(path string) bool  { return path == f.callbackPath }
func (f *fakeOverrideIssuer) Log() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (f *fakeOverrideIssuer) CompleteLogin(w http.ResponseWriter, r *http.Request, claims *Claims, flow CompletedFlow) error {
	f.called = true
	f.gotClaims = claims
	f.gotFlow = flow
	if f.completeErr != nil {
		return f.completeErr
	}
	w.Header().Set("X-Fake-Extra", flow.Extra)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("completed"))
	return nil
}

// bareSessionIssuer implements only [SessionIssuer] — neither
// [DefaultCompleter] nor [CompletionOverride] — to exercise
// [NewAuthenticator]'s construction-time requirement that at least one be
// present.
type bareSessionIssuer struct{ callbackPath string }

func (b bareSessionIssuer) SafeReturnTo(string) string { return "/" }
func (b bareSessionIssuer) IsExempt(path string) bool  { return path == b.callbackPath }
func (b bareSessionIssuer) Log() *slog.Logger          { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestNewAuthenticator_RequiresCompleterOrOverride(t *testing.T) {
	sess := bareSessionIssuer{callbackPath: defaultCallbackPath}
	cfg := AuthenticatorConfig{
		Issuer: "i", ClientID: "c", RedirectURL: "r", Verifier: stubTok{},
		FlowCookie: sealedcookie.Cookie{Key: testKey, Name: "test_flow", Path: "/"},
	}
	if _, err := NewAuthenticator(cfg, sess); err == nil {
		t.Error("want error when the session issuer implements neither DefaultCompleter nor CompletionOverride")
	}
}

func TestCompletionOverride_TakesPrecedenceAndCarriesExtra(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	defer tokenSrv.Close()

	stub := stubTok{}
	issuer := &fakeOverrideIssuer{callbackPath: defaultCallbackPath}
	cfg := AuthenticatorConfig{
		Issuer: tokenSrv.URL, ClientID: "c", RedirectURL: "r", Verifier: stub,
		FlowCookie: sealedcookie.Cookie{Key: testKey, Name: "test_flow", Path: "/"},
	}
	a, err := NewAuthenticator(cfg, issuer)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	// Begin with a non-empty Extra (e.g. vault's cli_callback), matching
	// how a CLI-loopback-flow caller would invoke it directly instead of
	// LoginHandler (which always passes "").
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	authURL, err := a.Begin(w, req, "cli-loopback-token")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if authURL == "" {
		t.Fatal("Begin returned empty authURL")
	}
	var fc *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == a.flow.Name {
			fc = c
		}
	}
	if fc == nil {
		t.Fatal("Begin set no flow cookie")
	}
	var flow oidcFlow
	if err := sealedcookie.Open(a.flow.Key, fc.Value, &flow); err != nil {
		t.Fatalf("open flow cookie: %v", err)
	}

	stub.claims = &Claims{Subject: "u-1", Email: "cli@x", Nonce: flow.Nonce}
	a.cfg.Verifier = stub

	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(flow.State)+"&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)

	if !issuer.called {
		t.Fatal("CompleteLogin was not called — DefaultCompleter path ran instead")
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "completed" {
		t.Fatalf("callback code=%d body=%q, want 200 completed (from CompleteLogin, not a redirect)", rec.Code, rec.Body.String())
	}
	if issuer.gotFlow.Extra != "cli-loopback-token" {
		t.Errorf("CompletedFlow.Extra = %q, want %q", issuer.gotFlow.Extra, "cli-loopback-token")
	}
	if issuer.gotClaims.Email != "cli@x" {
		t.Errorf("CompleteLogin claims.Email = %q, want cli@x", issuer.gotClaims.Email)
	}
}

func TestCompletionOverride_ErrorRenders500(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	defer tokenSrv.Close()

	stub := stubTok{}
	issuer := &fakeOverrideIssuer{callbackPath: defaultCallbackPath, completeErr: errBoom}
	cfg := AuthenticatorConfig{
		Issuer: tokenSrv.URL, ClientID: "c", RedirectURL: "r", Verifier: stub,
		FlowCookie: sealedcookie.Cookie{Key: testKey, Name: "test_flow", Path: "/"},
	}
	a, err := NewAuthenticator(cfg, issuer)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	authURL, err := a.Begin(w, req, "")
	if err != nil || authURL == "" {
		t.Fatalf("Begin: authURL=%q err=%v", authURL, err)
	}
	var fc *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == a.flow.Name {
			fc = c
		}
	}
	var flow oidcFlow
	if err := sealedcookie.Open(a.flow.Key, fc.Value, &flow); err != nil {
		t.Fatalf("open flow cookie: %v", err)
	}
	stub.claims = &Claims{Subject: "u-1", Nonce: flow.Nonce}
	a.cfg.Verifier = stub

	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(flow.State)+"&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("callback code = %d, want 500", rec.Code)
	}
	if !issuer.called {
		t.Fatal("CompleteLogin was not called")
	}
}

var errBoom = errors.New("boom")
