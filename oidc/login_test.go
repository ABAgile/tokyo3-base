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

	"golang.org/x/oauth2"

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
	flow := openFlow(t, a, fc)
	if flow.ReturnTo != "/portal/" {
		t.Errorf("fallback return_to = %q, want /portal/ (no return_to given)", flow.ReturnTo)
	}
	if fc.Path != "/portal" {
		t.Errorf("flow cookie path = %q, want /portal (shares the session cookie's scope)", fc.Path)
	}
}

// openFlow unseals the flow cookie and returns its newest pending flow.
func openFlow(t *testing.T, a *Authenticator, fc *http.Cookie) oidcFlow {
	t.Helper()
	var set oidcFlowSet
	if err := a.flow.Open(fc.Value, &set); err != nil {
		t.Fatalf("open flow cookie: %v", err)
	}
	if len(set.Flows) == 0 {
		t.Fatal("flow cookie holds no flows")
	}
	return set.Flows[len(set.Flows)-1]
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
	flow := openFlow(t, a, fc)
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
	stub.claims = &Claims{Subject: "u-1", Email: "alice@x", Groups: []string{"admins"}, Nonce: flow.Nonce, SessionID: "sid-7"}
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
	if err := (sealedcookie.Cookie{Key: a.flow.Key, Name: sc.Name}).Open(sc.Value, &sess); err != nil {
		t.Fatalf("open session: %v", err)
	}
	if sess.Email != "alice@x" || len(sess.Groups) != 1 || sess.Groups[0] != "admins" {
		t.Errorf("session = %+v", sess)
	}
	if sess.CSRFSecret == "" {
		t.Error("callback minted no CSRF secret")
	}
	if sess.SID != "sid-7" {
		t.Errorf("session SID = %q, want the IdP sid so back-channel logout can match it", sess.SID)
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
	if err := (sealedcookie.Cookie{Key: a.flow.Key, Name: sc.Name}).Open(sc.Value, &sess); err != nil {
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

func TestCallback_EmptySubjectRefused(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	defer tokenSrv.Close()
	stub := stubTok{}
	a := testAuth(t, stub, func(c *AuthenticatorConfig) { c.Issuer = tokenSrv.URL })
	fc, flow := startFlow(t, a)
	stub.claims = &Claims{Email: "alice@x", Nonce: flow.Nonce} // no sub
	a.cfg.Verifier = stub
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(flow.State)+"&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 for a token without sub", rec.Code)
	}
	if otherCookie(rec.Result().Cookies(), a.flow.Name) != nil {
		t.Error("a session cookie was issued for a subject-less token")
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
	flow := openFlow(t, a, fc)

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
	flow := openFlow(t, a, fc)
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

// ── Discovery-based endpoint resolution ───────────────────────────────

// syncEndpointStub implements TokenVerifier plus the sync Endpoint() shape
// HTTPVerifier exposes, so Authenticator resolves endpoints via discovery
// instead of the hardcoded {issuer}/authorize + {issuer}/token convention.
type syncEndpointStub struct {
	stubTok
	ep oauth2.Endpoint
}

func (s syncEndpointStub) Endpoint() oauth2.Endpoint { return s.ep }

// asyncEndpointStub implements TokenVerifier plus the ctx-taking Endpoint
// shape LazyVerifier exposes.
type asyncEndpointStub struct {
	stubTok
	ep  oauth2.Endpoint
	err error
}

func (a asyncEndpointStub) Endpoint(context.Context) (oauth2.Endpoint, error) { return a.ep, a.err }

func TestBegin_FallsBackToHardcodedConventionWithoutEndpoint(t *testing.T) {
	a := testAuth(t, stubTok{}, func(c *AuthenticatorConfig) { c.Issuer = "https://idp.example.com" })
	w := httptest.NewRecorder()
	authURL, err := a.Begin(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil), "")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if !strings.HasPrefix(authURL, "https://idp.example.com/authorize?") {
		t.Errorf("authURL = %q, want the hardcoded {issuer}/authorize convention", authURL)
	}
}

func TestBegin_UsesSyncDiscoveredEndpoint(t *testing.T) {
	ver := syncEndpointStub{ep: oauth2.Endpoint{
		AuthURL:  "https://discovered.example/oauth2/v1/authorize",
		TokenURL: "https://discovered.example/oauth2/v1/token",
	}}
	a := testAuth(t, ver, func(c *AuthenticatorConfig) { c.Issuer = "https://idp.example.com" })
	w := httptest.NewRecorder()
	authURL, err := a.Begin(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil), "")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if !strings.HasPrefix(authURL, "https://discovered.example/oauth2/v1/authorize?") {
		t.Errorf("authURL = %q, want the sync-discovered endpoint, not the hardcoded convention", authURL)
	}
}

func TestBegin_UsesAsyncDiscoveredEndpoint(t *testing.T) {
	ver := asyncEndpointStub{ep: oauth2.Endpoint{
		AuthURL:  "https://discovered.example/authorize",
		TokenURL: "https://discovered.example/token",
	}}
	a := testAuth(t, ver, func(c *AuthenticatorConfig) { c.Issuer = "https://idp.example.com" })
	w := httptest.NewRecorder()
	authURL, err := a.Begin(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil), "")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if !strings.HasPrefix(authURL, "https://discovered.example/authorize?") {
		t.Errorf("authURL = %q, want the async-discovered endpoint, not the hardcoded convention", authURL)
	}
}

func TestBegin_AsyncDiscoveryFailure_ReturnsError(t *testing.T) {
	ver := asyncEndpointStub{err: errBoom}
	a := testAuth(t, ver, func(c *AuthenticatorConfig) { c.Issuer = "https://idp.example.com" })
	w := httptest.NewRecorder()
	if _, err := a.Begin(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil), ""); err == nil {
		t.Error("want error when the verifier's discovery fails, not a silent fallback to the hardcoded convention")
	}
}

// TestLoginCallback_UsesDiscoveredTokenURL proves the token exchange POSTs
// to the DISCOVERED token endpoint rather than {Issuer}/token: Issuer is a
// non-resolvable placeholder, so the callback can only succeed if
// oidcclient.PostTokenAt actually used the verifier's discovered TokenURL
// (the real httptest server).
func TestLoginCallback_UsesDiscoveredTokenURL(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	defer tokenSrv.Close()

	stub := stubTok{}
	ver := syncEndpointStub{stubTok: stub, ep: oauth2.Endpoint{
		AuthURL:  "https://issuer.invalid/authorize",
		TokenURL: tokenSrv.URL + "/token",
	}}
	a := testAuth(t, ver, func(c *AuthenticatorConfig) { c.Issuer = "https://issuer.invalid" })
	fc, flow := startFlow(t, a)

	stub.claims = &Claims{Subject: "u-1", Email: "alice@x", Nonce: flow.Nonce}
	ver.stubTok = stub
	a.cfg.Verifier = ver

	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(flow.State)+"&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback code = %d body=%q, want 303 (exchange must have hit the discovered token URL, not the unresolvable issuer)", rec.Code, rec.Body.String())
	}
}

func TestCallback_AsyncDiscoveryFailure_502(t *testing.T) {
	ver := asyncEndpointStub{err: errBoom}
	a := testAuth(t, stubTok{}, func(c *AuthenticatorConfig) { c.Issuer = "https://idp.example.com" })
	fc, flow := startFlow(t, a)

	// Swap in the failing-discovery verifier only for the callback, after
	// Begin (which used the stub) has already sealed the flow cookie.
	a.cfg.Verifier = ver

	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(flow.State)+"&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("callback code = %d, want 502 when endpoint discovery fails", rec.Code)
	}
}

// beginLogin runs LoginHandler carrying prior and returns the flow cookie the
// response (re)set.
func beginLogin(t *testing.T, a *Authenticator, prior *http.Cookie) *http.Cookie {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	if prior != nil {
		r.AddCookie(prior)
	}
	rec := httptest.NewRecorder()
	a.LoginHandler()(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.Name == a.flow.Name {
			return c
		}
	}
	t.Fatal("login set no flow cookie")
	return nil
}

func flowsIn(t *testing.T, a *Authenticator, fc *http.Cookie) []oidcFlow {
	t.Helper()
	var set oidcFlowSet
	if err := a.flow.Open(fc.Value, &set); err != nil {
		t.Fatalf("open flow cookie: %v", err)
	}
	return set.Flows
}

func tokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The flow cookie's lifetime is enforced from the sealed payload, not just by
// the browser's Max-Age.
func TestCallback_FlowExpiryEnforcedFromPayload(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	fc, flow := startFlow(t, a)
	base := a.flow.Now()
	a.flow.Now = func() time.Time { return base.Add(flowTTL + time.Second) }

	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(flow.State)+"&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("code=%d body=%q, want 400 expired", rec.Code, rec.Body.String())
	}
}

// Two logins started in different tabs both complete: the second Begin must not
// clobber the first's state, and finishing one leaves the other pending.
func TestCallback_ConcurrentLoginsBothComplete(t *testing.T) {
	srv := tokenServer(t)
	a := testAuth(t, stubTok{}, func(c *AuthenticatorConfig) { c.Issuer = srv.URL })

	c1 := beginLogin(t, a, nil)
	c2 := beginLogin(t, a, c1)
	flows := flowsIn(t, a, c2)
	if len(flows) != 2 {
		t.Fatalf("flows after two logins = %d, want 2", len(flows))
	}

	callback := func(cookie *http.Cookie, f oidcFlow) *httptest.ResponseRecorder {
		a.cfg.Verifier = stubTok{claims: &Claims{Subject: "u", Nonce: f.Nonce}}
		r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(f.State)+"&code=abc", nil)
		r.AddCookie(cookie)
		rec := httptest.NewRecorder()
		a.CallbackHandler()(rec, r)
		return rec
	}

	rec := callback(c2, flows[0])
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("first login callback = %d %q", rec.Code, rec.Body.String())
	}
	var rest *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == a.flow.Name {
			rest = c
		}
	}
	if rest == nil || rest.MaxAge < 0 {
		t.Fatalf("flow cookie after first callback = %+v, want the second login still pending", rest)
	}
	if left := flowsIn(t, a, rest); len(left) != 1 || left[0].State != flows[1].State {
		t.Fatalf("pending after first callback = %+v, want only the second flow", left)
	}

	if rec := callback(rest, flows[1]); rec.Code != http.StatusSeeOther {
		t.Fatalf("second login callback = %d %q", rec.Code, rec.Body.String())
	}
}

func TestBegin_PendingFlowsAreCapped(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	var fc *http.Cookie
	var states []string
	for range maxPendingFlows + 2 {
		fc = beginLogin(t, a, fc)
		states = append(states, openFlow(t, a, fc).State)
	}
	flows := flowsIn(t, a, fc)
	if len(flows) != maxPendingFlows {
		t.Fatalf("pending flows = %d, want %d", len(flows), maxPendingFlows)
	}
	if flows[0].State != states[2] || flows[len(flows)-1].State != states[len(states)-1] {
		t.Error("cap must drop the oldest flows and keep the newest")
	}
}

// A callback whose state matches nothing must not wipe the user's legitimate
// pending logins.
func TestCallback_UnknownStateLeavesFlowCookieAlone(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	fc, _ := startFlow(t, a)
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state=WRONG&code=abc", nil)
	r.AddCookie(fc)
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == a.flow.Name {
			t.Fatalf("forged callback modified the flow cookie: %+v", c)
		}
	}
}

func TestCallback_RequireVerifiedEmail(t *testing.T) {
	srv := tokenServer(t)
	for _, tc := range []struct {
		name     string
		require  bool
		verified bool
		want     int
	}{
		{"required, unverified", true, false, http.StatusUnauthorized},
		{"required, verified", true, true, http.StatusSeeOther},
		{"not required, unverified", false, false, http.StatusSeeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testAuth(t, stubTok{}, func(c *AuthenticatorConfig) {
				c.Issuer = srv.URL
				c.RequireVerifiedEmail = tc.require
			})
			fc, flow := startFlow(t, a)
			a.cfg.Verifier = stubTok{claims: &Claims{Subject: "u", Email: "a@x", EmailVerified: tc.verified, Nonce: flow.Nonce}}
			r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(flow.State)+"&code=abc", nil)
			r.AddCookie(fc)
			rec := httptest.NewRecorder()
			a.CallbackHandler()(rec, r)
			if rec.Code != tc.want {
				t.Fatalf("code = %d body=%q, want %d", rec.Code, rec.Body.String(), tc.want)
			}
			if tc.want == http.StatusUnauthorized && otherCookie(rec.Result().Cookies(), a.flow.Name) != nil {
				t.Error("session issued despite unverified email")
			}
		})
	}
}
