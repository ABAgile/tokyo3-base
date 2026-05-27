package oidcclient_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/auth/oidcclient"
)

// deviceFixture stands up an httptest server exposing
// /device_authorization + /token in the shape RFC 8628 requires. The
// /token handler is driven by a per-call response function so each
// test scripts its own polling progression (pending → success,
// pending → denied, etc.).
type deviceFixture struct {
	srv         *httptest.Server
	polls       atomic.Int32
	deviceCode  string
	userCode    string
	interval    int
	expiresIn   int
	tokenHandle func(int32, http.ResponseWriter)
}

func newDeviceFixture(t *testing.T) *deviceFixture {
	t.Helper()
	f := &deviceFixture{
		deviceCode: "dc-abc",
		userCode:   "ABCD-WXYZ",
		interval:   1, // 1s polling cadence keeps tests under ~3s
		expiresIn:  60,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device_authorization":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":               f.deviceCode,
				"user_code":                 f.userCode,
				"verification_uri":          "https://issuer.test/device",
				"verification_uri_complete": "https://issuer.test/device?user_code=" + f.userCode,
				"expires_in":                f.expiresIn,
				"interval":                  f.interval,
			})
		case "/token":
			n := f.polls.Add(1)
			if f.tokenHandle != nil {
				f.tokenHandle(n, w)
				return
			}
			http.Error(w, "no token handler configured", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// writeTokenSuccess writes a well-formed 200 OAuth2 token response.
func writeTokenSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{
		"access_token":  "at-final",
		"refresh_token": "rt-final",
		"id_token":      "it-final",
		"expires_in":    3600
	}`))
}

// writeTokenError writes a 400 with the RFC 8628 error code shape.
func writeTokenError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`{"error":"` + code + `","error_description":"` + desc + `"}`))
}

// TestRunDeviceFlow_HappyPath: server returns pending once, then
// success. Exercises the canonical "user approves on phone, CLI keeps
// polling" sequence and confirms the final Tokens are populated.
func TestRunDeviceFlow_HappyPath(t *testing.T) {
	f := newDeviceFixture(t)
	f.tokenHandle = func(n int32, w http.ResponseWriter) {
		if n == 1 {
			writeTokenError(w, "authorization_pending", "still waiting")
			return
		}
		writeTokenSuccess(w)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, err := oidcclient.RunDeviceFlow(ctx, f.srv.URL, "cli-client", io.Discard)
	if err != nil {
		t.Fatalf("RunDeviceFlow: %v", err)
	}
	if tok.AccessToken != "at-final" || tok.RefreshToken != "rt-final" || tok.IDToken != "it-final" {
		t.Errorf("tokens not propagated: %+v", tok)
	}
	if d := time.Until(tok.Expiration); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("Expiration ~ %v, want ~1h", d)
	}
	if got := f.polls.Load(); got < 2 {
		t.Errorf("expected at least 2 polls, got %d", got)
	}
}

// TestRunDeviceFlow_AccessDenied: server returns access_denied on
// the first poll. The CLI must stop polling immediately and surface
// a clear error rather than waiting for timeout.
func TestRunDeviceFlow_AccessDenied(t *testing.T) {
	f := newDeviceFixture(t)
	f.tokenHandle = func(_ int32, w http.ResponseWriter) {
		writeTokenError(w, "access_denied", "user denied")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := oidcclient.RunDeviceFlow(ctx, f.srv.URL, "cli-client", io.Discard)
	if err == nil {
		t.Fatal("RunDeviceFlow: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("error %q does not mention denial", err.Error())
	}
}

// TestRunDeviceFlow_ExpiredToken: server returns expired_token. The
// CLI must surface an error mentioning expiry so the user knows to
// restart rather than retry.
func TestRunDeviceFlow_ExpiredToken(t *testing.T) {
	f := newDeviceFixture(t)
	f.tokenHandle = func(_ int32, w http.ResponseWriter) {
		writeTokenError(w, "expired_token", "device code expired")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := oidcclient.RunDeviceFlow(ctx, f.srv.URL, "cli-client", io.Discard)
	if err == nil {
		t.Fatal("RunDeviceFlow: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error %q does not mention expiry", err.Error())
	}
}

// TestRunDeviceFlow_SlowDownBackoff: server returns slow_down on
// first poll, then success. The package should honour the backoff
// (interval bumped) without aborting.
func TestRunDeviceFlow_SlowDownBackoff(t *testing.T) {
	f := newDeviceFixture(t)
	f.tokenHandle = func(n int32, w http.ResponseWriter) {
		if n == 1 {
			writeTokenError(w, "slow_down", "polling too fast")
			return
		}
		writeTokenSuccess(w)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, err := oidcclient.RunDeviceFlow(ctx, f.srv.URL, "cli-client", io.Discard)
	if err != nil {
		t.Fatalf("RunDeviceFlow: %v", err)
	}
	if tok.AccessToken != "at-final" {
		t.Errorf("AccessToken = %q, want at-final", tok.AccessToken)
	}
}

// TestRunDeviceFlow_UnknownErrorAborts: an error code the package
// doesn't recognise (anything other than authorization_pending /
// slow_down / access_denied / expired_token) must be treated as
// terminal — polling forever on an unrecognised code would be worse
// than failing cleanly.
func TestRunDeviceFlow_UnknownErrorAborts(t *testing.T) {
	f := newDeviceFixture(t)
	f.tokenHandle = func(_ int32, w http.ResponseWriter) {
		writeTokenError(w, "server_error", "something bad")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := oidcclient.RunDeviceFlow(ctx, f.srv.URL, "cli-client", io.Discard)
	if err == nil {
		t.Fatal("RunDeviceFlow: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "server_error") {
		t.Errorf("error %q does not name the underlying code", err.Error())
	}
}

// TestRunDeviceFlow_CtxCancelAborts: cancelling the context during
// the polling sleep must cause RunDeviceFlow to return ctx.Err()
// promptly rather than waiting out the expires_in deadline. Critical
// for CLIs that want clean SIGINT handling.
func TestRunDeviceFlow_CtxCancelAborts(t *testing.T) {
	f := newDeviceFixture(t)
	f.expiresIn = 60
	f.tokenHandle = func(_ int32, w http.ResponseWriter) {
		writeTokenError(w, "authorization_pending", "waiting")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := oidcclient.RunDeviceFlow(ctx, f.srv.URL, "cli-client", io.Discard)
		done <- err
	}()
	// Give the first poll a moment to land, then cancel.
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RunDeviceFlow: expected error after cancel, got nil")
		}
		// Cancellation during the sleep returns ctx.Err(); cancellation
		// during the HTTP call returns a transport error wrapping it.
		// Either is acceptable — both stop the loop promptly.
	case <-time.After(3 * time.Second):
		t.Fatal("RunDeviceFlow did not exit within 3s of cancel")
	}
}

// TestRunDeviceFlow_AuthzEndpointError: a non-200 from
// /device_authorization aborts before any polling starts. The error
// should surface the upstream status so the operator can debug.
func TestRunDeviceFlow_AuthzEndpointError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "client_id not registered", http.StatusUnauthorized)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := oidcclient.RunDeviceFlow(ctx, srv.URL, "cli-client", io.Discard)
	if err == nil {
		t.Fatal("RunDeviceFlow: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q does not include status code 401", err.Error())
	}
}

// TestLogin_DevicePersistsConfigAndTokens: end-to-end via the Login
// entry point. After Login returns, both config.json and tokens.json
// must be on disk with the expected values, so a subsequent process
// can LoadConfig / LoadTokens without re-running the flow.
func TestLogin_DevicePersistsConfigAndTokens(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp)

	f := newDeviceFixture(t)
	f.tokenHandle = func(_ int32, w http.ResponseWriter) {
		writeTokenSuccess(w)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := oidcclient.Config{Issuer: f.srv.URL, ClientID: "cli-client"}
	tokens, err := oidcclient.Login(ctx, cfg, oidcclient.LoginOptions{Device: true, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tokens.AccessToken != "at-final" {
		t.Errorf("returned AccessToken = %q, want at-final", tokens.AccessToken)
	}

	// Persisted state is the actual contract — a fresh process must be
	// able to find what Login wrote.
	gotCfg, err := oidcclient.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig after Login: %v", err)
	}
	if gotCfg.Issuer != f.srv.URL || gotCfg.ClientID != "cli-client" {
		t.Errorf("LoadConfig = %+v, want issuer=%s client_id=cli-client", *gotCfg, f.srv.URL)
	}
	gotTok, err := oidcclient.LoadTokens()
	if err != nil {
		t.Fatalf("LoadTokens after Login: %v", err)
	}
	if gotTok.AccessToken != "at-final" || gotTok.RefreshToken != "rt-final" {
		t.Errorf("LoadTokens = %+v, want at-final/rt-final", gotTok)
	}
}

// TestLogin_RejectsEmptyConfig: cheap fast-fail on empty Issuer or
// ClientID — the network round-trip would just produce a server-side
// error, so the package short-circuits.
func TestLogin_RejectsEmptyConfig(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp)

	for _, cfg := range []oidcclient.Config{
		{}, // both empty
		{Issuer: "https://issuer.test"},
		{ClientID: "client"},
	} {
		_, err := oidcclient.Login(context.Background(), cfg, oidcclient.LoginOptions{Stderr: io.Discard})
		if err == nil {
			t.Errorf("Login with %+v: expected error, got nil", cfg)
		}
	}
}
