package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/session"
)

// rejectVerifier stands in for an ID token that fails signature, issuer, or
// audience checks.
type rejectVerifier struct{}

func (rejectVerifier) Verify(context.Context, string) (*Claims, error) {
	return nil, errors.New("signature does not verify")
}

// clearedFlowCookie reports whether cookies clear the named flow cookie.
func clearedFlowCookie(cookies []*http.Cookie, name string) bool {
	for _, c := range cookies {
		if c.Name == name && (c.Value == "" || c.MaxAge < 0) {
			return true
		}
	}
	return false
}

func callbackRequest(state, code string, flowCookie *http.Cookie) *http.Request {
	q := "/auth/callback?state=" + url.QueryEscape(state)
	if code != "" {
		q += "&code=" + url.QueryEscape(code)
	}
	r := httptest.NewRequest(http.MethodGet, q, nil)
	r.AddCookie(flowCookie)
	return r
}

func TestCallback_MissingCodeIs400WithoutSession(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	fc, flow := startFlow(t, a)

	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, callbackRequest(flow.State, "", fc))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400 for a callback with no authorization code", rec.Code)
	}
	if otherCookie(rec.Result().Cookies(), a.flow.Name) != nil {
		t.Error("a session cookie was issued without an authorization code")
	}
}

// The token request must carry the confidential client secret and the PKCE
// verifier. Dropping either breaks the exchange, and the IdP rejects it.
func TestCallback_TokenRequestCarriesClientSecretAndPKCEVerifier(t *testing.T) {
	forms := make(chan url.Values, 1)
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		forms <- r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	defer tokenSrv.Close()

	stub := stubTok{}
	a := testAuth(t, stub, func(c *AuthenticatorConfig) {
		c.Issuer = tokenSrv.URL
		c.ClientSecret = "s3cret-client"
	})
	fc, flow := startFlow(t, a)
	stub.claims = &Claims{Subject: "u-1", Email: "alice@x", Nonce: flow.Nonce}
	a.cfg.Verifier = stub

	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, callbackRequest(flow.State, "abc", fc))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback code = %d body=%q", rec.Code, rec.Body.String())
	}

	form := <-forms
	want := map[string]string{
		"grant_type":    "authorization_code",
		"code":          "abc",
		"redirect_uri":  a.cfg.RedirectURL,
		"client_id":     a.cfg.ClientID,
		"client_secret": "s3cret-client",
		"code_verifier": flow.Verifier,
	}
	for k, v := range want {
		if got := form.Get(k); got != v {
			t.Errorf("token request %s = %q, want %q", k, got, v)
		}
	}
}

// A token endpoint failure is a gateway error, and no session may be issued.
func TestCallback_TokenExchangeFailureIs502(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
	}))
	defer tokenSrv.Close()

	a := testAuth(t, stubTok{}, func(c *AuthenticatorConfig) { c.Issuer = tokenSrv.URL })
	fc, flow := startFlow(t, a)

	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, callbackRequest(flow.State, "abc", fc))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502 when the token exchange fails", rec.Code)
	}
	if otherCookie(rec.Result().Cookies(), a.flow.Name) != nil {
		t.Error("a session cookie was issued after a failed token exchange")
	}
}

// An ID token that fails verification must be refused before any claims are
// trusted, so no session is issued.
func TestCallback_IDTokenVerifyFailureIs401(t *testing.T) {
	tokenSrv := tokenServer(t)
	a := testAuth(t, rejectVerifier{}, func(c *AuthenticatorConfig) { c.Issuer = tokenSrv.URL })
	fc, flow := startFlow(t, a)

	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, callbackRequest(flow.State, "abc", fc))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 for an ID token that does not verify", rec.Code)
	}
	if otherCookie(rec.Result().Cookies(), a.flow.Name) != nil {
		t.Error("a session cookie was issued for an unverified ID token")
	}
}

// A return_to too large to seal into the flow cookie must fail the login
// closed with a 500, not start a flow it cannot track.
func TestLoginHandler_OversizedReturnToFailsClosed(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	huge := "/" + strings.Repeat("a", 8000)
	rec := httptest.NewRecorder()
	a.LoginHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+huge, nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500 when the flow cannot be stored", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == a.flow.Name && c.Value != "" {
			t.Error("a flow cookie was set despite the failed login")
		}
	}
}

// With several logins in flight the combined flow cookie can outgrow the
// cookie limit. The new login must then fall back to a cookie holding only
// itself, rather than failing.
func TestBegin_FallsBackToNewFlowOnlyWhenPendingSetOverflows(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	padded := "/" + strings.Repeat("p", 1200) // each pending flow is about 1.8 KB sealed
	login := func(prior *http.Cookie, tag string) *http.Cookie {
		r := httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+padded+tag, nil)
		if prior != nil {
			r.AddCookie(prior)
		}
		rec := httptest.NewRecorder()
		authURL, err := a.Begin(rec, r, "")
		if err != nil {
			t.Fatalf("Begin(%s): %v", tag, err)
		}
		if authURL == "" {
			t.Fatalf("Begin(%s) returned no authorize URL", tag)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == a.flow.Name {
				return c
			}
		}
		t.Fatalf("Begin(%s) set no flow cookie", tag)
		return nil
	}

	var fc *http.Cookie
	for _, tag := range []string{"1", "2"} {
		fc = login(fc, tag)
	}
	if n := len(flowsIn(t, a, fc)); n != 2 {
		t.Fatalf("setup: %d pending flows, want 2", n)
	}

	// A third login would exceed the cookie limit alongside the other two.
	fc = login(fc, "3")
	flows := flowsIn(t, a, fc)
	if len(flows) != 1 {
		t.Fatalf("after overflow: %d flows in cookie, want only the new login", len(flows))
	}
	if !strings.HasSuffix(flows[0].ReturnTo, "3") {
		t.Errorf("surviving flow is not the new login: ReturnTo ends %q", flows[0].ReturnTo[len(flows[0].ReturnTo)-4:])
	}
}

// consumeFlow must not wipe the user's pending logins when a forged callback
// names no flow at all.
func TestConsumeFlow_NegativeIndexLeavesCookieAlone(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	rec := httptest.NewRecorder()
	a.consumeFlow(rec, httptest.NewRequest(http.MethodGet, "/auth/callback", nil), []oidcFlow{{State: "s"}}, -1)
	if n := len(rec.Result().Cookies()); n != 0 {
		t.Errorf("consumeFlow(-1) wrote %d cookie(s), want none", n)
	}
}

// If the remaining pending flows cannot be sealed back into the flow cookie,
// the cookie is cleared and a warning is logged. The login itself still
// completes, because the flow it started has already been matched.
func TestCallback_PendingFlowReSealFailureClearsCookieAndCompletes(t *testing.T) {
	forms := make(chan url.Values, 1)
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		forms <- r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	defer tokenSrv.Close()

	logs := &bytes.Buffer{}
	stub := stubTok{}
	sm := testSessionManager(t, func(c *session.Config) {
		c.Log = slog.New(slog.NewTextHandler(logs, nil))
	})
	a := testAuthWith(t, stub, func(c *AuthenticatorConfig) { c.Issuer = tokenSrv.URL }, sm)

	fc, flow := startFlow(t, a)
	// A sibling pending flow too large to seal once the matched flow is
	// removed. The cookie is sealed directly, because a Set would refuse it.
	other := oidcFlow{
		State:    "other-state",
		Nonce:    "other-nonce",
		Verifier: "other-verifier",
		ReturnTo: "/" + strings.Repeat("x", 6000),
		Exp:      a.now().Add(flowTTL).Unix(),
	}
	sealed, err := a.flow.Seal(oidcFlowSet{Flows: []oidcFlow{flow, other}})
	if err != nil {
		t.Fatal(err)
	}
	fc = &http.Cookie{Name: fc.Name, Value: sealed}

	stub.claims = &Claims{Subject: "u-1", Email: "alice@x", Nonce: flow.Nonce}
	a.cfg.Verifier = stub
	rec := httptest.NewRecorder()
	a.CallbackHandler()(rec, callbackRequest(flow.State, "abc", fc))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback code = %d, want the login to complete; body=%q", rec.Code, rec.Body.String())
	}
	if !clearedFlowCookie(rec.Result().Cookies(), a.flow.Name) {
		t.Error("flow cookie not cleared after its pending flows could not be re-sealed")
	}
	if !strings.Contains(logs.String(), "re-seal pending flows failed") {
		t.Errorf("re-seal failure not logged: %q", logs.String())
	}
}
