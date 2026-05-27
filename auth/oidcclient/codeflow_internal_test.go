package oidcclient

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// codeFlowFixture stands up a fake issuer that serves the /token
// endpoint and supplies a mock openBrowser that drives the loopback
// callback directly. Tests use the public RunCodeFlow API exactly as
// production callers do; the seam is just the package-level
// openBrowser var, swapped under a sync.Mutex so concurrent tests
// can't corrupt each other.
type codeFlowFixture struct {
	t          *testing.T
	srv        *httptest.Server
	tokenResp  string // raw body the /token endpoint returns on 200
	tokenCode  int    // override status (0 = 200)
	browserErr error  // injected error from openBrowser, if any
	// scripted callback values — defaults to a real "approval"
	// (matching state, real code). Override for negative tests.
	overrideCode  string // if non-empty, used as the ?code= value
	overrideState string // if non-empty, used as the ?state= value (mismatch test)
	skipCallback  bool   // if true, openBrowser doesn't fire the callback at all
}

// reset locks the openBrowser var for the duration of a single test.
// Subsequent fixture-driven tests must wait — this is the price of
// having a package-level seam.
var openBrowserMu sync.Mutex

func newCodeFlowFixture(t *testing.T) *codeFlowFixture {
	t.Helper()
	f := &codeFlowFixture{
		t:         t,
		tokenResp: `{"access_token":"at-code","refresh_token":"rt-code","id_token":"it-code","expires_in":3600}`,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if f.tokenCode != 0 {
			http.Error(w, f.tokenResp, f.tokenCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.tokenResp))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// install swaps openBrowser with the fixture's mock for the duration
// of the test, restoring the original on cleanup. The mock parses
// the authorize URL the package produces, extracts redirect_uri +
// state, and POSTs back to the loopback /callback so RunCodeFlow's
// listener can resolve.
func (f *codeFlowFixture) install() {
	openBrowserMu.Lock()
	original := openBrowser
	openBrowser = func(rawURL string) error {
		if f.browserErr != nil {
			return f.browserErr
		}
		if f.skipCallback {
			return nil
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			f.t.Errorf("openBrowser mock: parse authURL: %v", err)
			return nil
		}
		q := u.Query()
		redirect := q.Get("redirect_uri")
		state := q.Get("state")
		code := "code-from-issuer"
		if f.overrideCode != "" {
			code = f.overrideCode
		}
		if f.overrideState != "" {
			state = f.overrideState
		}
		// The callback handler resolves synchronously inside
		// RunCodeFlow's goroutine; we don't need to wait on it.
		go func() {
			// Small delay so RunCodeFlow's select{} is parked on
			// codeCh before we fire — otherwise the goroutine race
			// could surface a flake under load. 50ms is plenty.
			time.Sleep(50 * time.Millisecond)
			cb := redirect + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
			resp, err := http.Get(cb)
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
	f.t.Cleanup(func() {
		openBrowser = original
		openBrowserMu.Unlock()
	})
}

// TestRunCodeFlow_HappyPath drives the full code+PKCE flow against
// a mock issuer: the package opens a loopback listener, the mock
// browser fires a /callback that resolves with the issuer-provided
// code, exchangeCode swaps it for tokens at /token. End-to-end win
// is that RunCodeFlow returns the issuer's tokens.
func TestRunCodeFlow_HappyPath(t *testing.T) {
	f := newCodeFlowFixture(t)
	f.install()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, err := RunCodeFlow(ctx, f.srv.URL, "cli-client", 0, io.Discard)
	if err != nil {
		t.Fatalf("RunCodeFlow: %v", err)
	}
	if tok.AccessToken != "at-code" || tok.RefreshToken != "rt-code" || tok.IDToken != "it-code" {
		t.Errorf("tokens not propagated: %+v", tok)
	}
	if d := time.Until(tok.Expiration); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("Expiration ~ %v, want ~1h", d)
	}
}

// TestRunCodeFlow_StateMismatchAborts: the callback handler must
// reject a mismatched state (CSRF defence) and surface that as the
// error from RunCodeFlow rather than continuing to exchange the
// code.
func TestRunCodeFlow_StateMismatchAborts(t *testing.T) {
	f := newCodeFlowFixture(t)
	f.overrideState = "wrong-state-totally-different"
	f.install()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := RunCodeFlow(ctx, f.srv.URL, "cli-client", 0, io.Discard)
	if err == nil {
		t.Fatal("RunCodeFlow: expected state-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "state mismatch") {
		t.Errorf("error %q does not mention state mismatch", err.Error())
	}
}

// TestRunCodeFlow_TokenEndpointError: the issuer returns 400 from
// /token (e.g. expired code, PKCE failure). The error must surface
// the upstream status so the operator can debug.
func TestRunCodeFlow_TokenEndpointError(t *testing.T) {
	f := newCodeFlowFixture(t)
	f.tokenCode = http.StatusBadRequest
	f.tokenResp = "invalid_grant: code expired"
	f.install()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := RunCodeFlow(ctx, f.srv.URL, "cli-client", 0, io.Discard)
	if err == nil {
		t.Fatal("RunCodeFlow: expected token-endpoint error, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error %q does not include status code 400", err.Error())
	}
}

// TestRunCodeFlow_CtxCancelAborts: cancelling the context during
// the listener wait must cause RunCodeFlow to return promptly with
// ctx.Err(), not block for the 5-minute internal timeout. Critical
// for CLI SIGINT handling.
func TestRunCodeFlow_CtxCancelAborts(t *testing.T) {
	f := newCodeFlowFixture(t)
	f.skipCallback = true // listener will never see a callback
	f.install()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := RunCodeFlow(ctx, f.srv.URL, "cli-client", 0, io.Discard)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RunCodeFlow: expected error after cancel, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunCodeFlow did not exit within 3s of cancel")
	}
}

// TestRunCodeFlow_ListenFailure: bind a port ourselves, then ask
// RunCodeFlow to bind the same port — net.Listen fails with "address
// already in use", and RunCodeFlow must surface that as a clear
// "loopback listen" error rather than burning the user's 5-minute
// timeout waiting for a callback that can't arrive.
func TestRunCodeFlow_ListenFailure(t *testing.T) {
	openBrowserMu.Lock()
	defer openBrowserMu.Unlock()

	// Hold port 0 → kernel picks one, then we reuse it.
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("seed listen: %v", err)
	}
	defer hold.Close()
	port := hold.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = RunCodeFlow(ctx, "https://issuer.test", "cli-client", port, io.Discard)
	if err == nil {
		t.Fatal("RunCodeFlow: expected listen failure, got nil")
	}
	if !strings.Contains(err.Error(), "loopback listen") {
		t.Errorf("error %q does not name the listen failure source", err.Error())
	}
}
