package oidcclient

import (
	"context"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// requireBlockingLocks holds the token-cache lock for the rest of the test and
// skips the test when the platform's lock does not block a second holder. The
// non-Unix build (lock_other.go) has no lock, so there is nothing to time out.
// The caller must isolate the config directory first, since the lock lives there.
func requireBlockingLocks(t *testing.T) {
	t.Helper()
	unlock, err := lockTokens(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unlock)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if second, err := lockTokens(ctx); err == nil {
		second()
		t.Skip("platform has no blocking token-cache lock")
	}
}

// An IdP error on the callback ends the login with the IdP's reason. No token
// request is made.
func TestRunCodeFlow_IdPErrorFailsLogin(t *testing.T) {
	f := newCodeFlowFixture(t)
	f.callbackError = "access_denied"
	f.install()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := RunCodeFlow(ctx, f.srv.URL, "cli-client", 0, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("err = %v, want the IdP's access_denied error", err)
	}
}

// A callback that matches the state but carries no code is not an approval.
func TestRunCodeFlow_CallbackWithoutCodeFails(t *testing.T) {
	f := newCodeFlowFixture(t)
	f.omitCode = true
	f.install()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := RunCodeFlow(ctx, f.srv.URL, "cli-client", 0, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no code") {
		t.Fatalf("err = %v, want a no-code error", err)
	}
}

// Login with the code flow stores the tokens and the config that identifies
// their issuer, so a later refresh can prove the cache belongs to that issuer.
func TestLogin_CodeFlowStoresTokensBoundToConfig(t *testing.T) {
	isolateConfigHome(t)
	f := newCodeFlowFixture(t)
	f.install()
	cfg := Config{Issuer: f.srv.URL, ClientID: "cli-client"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tokens, err := Login(ctx, cfg, LoginOptions{Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tokens.AccessToken != "at-code" {
		t.Errorf("AccessToken = %q, want at-code", tokens.AccessToken)
	}
	if saved, err := LoadConfig(); err != nil || *saved != cfg {
		t.Errorf("saved config = %+v, %v; want %+v", saved, err, cfg)
	}
	if cached, err := LoadTokens(); err != nil || cached.AccessToken != "at-code" {
		t.Errorf("cached tokens = %+v, %v; want at-code", cached, err)
	}
}

// Login waits for the token-cache lock before it writes. If another holder keeps
// the lock past the deadline, Login fails and writes nothing.
func TestLogin_LockTimeoutWritesNothing(t *testing.T) {
	isolateConfigHome(t)
	requireBlockingLocks(t)
	f := newCodeFlowFixture(t)
	f.install()
	cfg := Config{Issuer: f.srv.URL, ClientID: "cli-client"}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	_, err := Login(ctx, cfg, LoginOptions{Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "lock token cache") {
		t.Fatalf("err = %v, want a lock-timeout error", err)
	}
	if tok, err := LoadTokens(); err == nil {
		t.Errorf("tokens were written despite the lock failure: %+v", tok)
	}
}

// A refresh the IdP rejects fails, and the error tells the user to log in
// again rather than returning the expired tokens.
func TestEnsureFreshTokens_RejectedRefreshAsksForLogin(t *testing.T) {
	isolateConfigHome(t)
	f := newCodeFlowFixture(t)
	f.tokenCode = http.StatusBadRequest
	f.tokenResp = `{"error":"invalid_grant"}`
	cfg := Config{Issuer: f.srv.URL, ClientID: "cli-client"}
	expired := &Tokens{AccessToken: "old", RefreshToken: "rt", Expiration: time.Now().Add(-time.Minute)}
	if err := saveTokens(expired, &cfg); err != nil {
		t.Fatal(err)
	}

	_, err := EnsureFreshTokens(context.Background(), cfg, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "run login again") {
		t.Fatalf("err = %v, want a refresh error that asks for a new login", err)
	}
}

// A refresh that cannot take the lock does not contact the IdP at all, and
// reports the lock timeout.
func TestEnsureFreshTokens_LockTimeoutDoesNotRefresh(t *testing.T) {
	isolateConfigHome(t)
	requireBlockingLocks(t)
	// The issuer is unreachable on purpose: reaching it would fail differently.
	cfg := Config{Issuer: "https://idp.example", ClientID: "cli"}
	expired := &Tokens{AccessToken: "old", RefreshToken: "rt", Expiration: time.Now().Add(-time.Minute)}
	if err := saveTokens(expired, &cfg); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := EnsureFreshTokens(ctx, cfg, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "lock token cache") {
		t.Fatalf("err = %v, want a lock-timeout error", err)
	}
}

// On a headless Linux session the default opener refuses before launching
// anything, and tells the user to open the URL themselves.
func TestOpenBrowser_HeadlessSessionRefuses(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("headless detection is Linux-only")
	}
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	openBrowserMu.Lock()
	defer openBrowserMu.Unlock()
	err := OpenBrowser("https://idp.example/authorize")
	if err == nil || !strings.Contains(err.Error(), "no display") {
		t.Fatalf("err = %v, want the headless refusal", err)
	}
}
