package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// defaultLoopbackTimeout bounds how long LoopbackCallback.Wait waits
// for the browser redirect before giving up. Long enough for a human
// to authenticate at the IdP (including MFA), short enough that a CLI
// invocation doesn't hang indefinitely if the user walks away.
const defaultLoopbackTimeout = 5 * time.Minute

// LoopbackListener binds a 127.0.0.1 listener on port (0 picks a free
// port) and returns it plus the redirect URI a browser-based flow
// should register — the resolved host:port combined with path. This
// is the shared "bind a loopback port, learn its redirect URI" step
// behind RunCodeFlow and any other CLI flow that opens a browser and
// waits for a redirect back to this process (e.g. a server-mediated
// login that hands back its own token rather than a raw OAuth code —
// see vault's `vault login --oidc`).
func LoopbackListener(port int, path string) (net.Listener, string, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, "", fmt.Errorf("loopback listen: %w", err)
	}
	return listener, fmt.Sprintf("http://%s%s", listener.Addr().String(), path), nil
}

// LoopbackCallback is a loopback HTTP server already accepting
// connections on path, waiting for exactly one callback request.
// Build with StartLoopbackCallback, open the browser (or otherwise
// trigger the redirect) only *after* that call returns — the server
// is already serving by then — and call Wait for the result.
//
// Splitting "start serving" from "wait for the result" (rather than a
// single blocking call) matters: opening the browser before the
// server is actually accepting connections risks the redirect
// arriving at a listener nobody is reading from yet. A real browser
// launch is non-blocking in practice (the OS process starts in the
// background while this process moves on to opening the listener),
// but this API makes the ordering structural rather than an implicit
// timing assumption callers have to get right on their own.
type LoopbackCallback struct {
	srv     *http.Server
	valueCh chan string
	errCh   chan error
}

// StartLoopbackCallback starts serving on listener at path and
// returns immediately — the server is accepting connections by the
// time this call returns, so the caller can safely open the browser
// next. handle inspects each request, writes the browser-facing
// response, and returns either a caller-defined success value or an
// error; only the first request's outcome is delivered by Wait.
//
// This is the shared "wait for exactly one browser redirect" mechanic
// behind RunCodeFlow (which waits for an OAuth ?code=/?state=
// callback) and vault's CLI login (which waits for a ?token=/?error=
// callback carrying a service-minted credential instead of a raw
// OAuth code) — both need identical bind/serve/timeout/shutdown
// boilerplate around a completely different payload.
func StartLoopbackCallback(listener net.Listener, path string, handle func(w http.ResponseWriter, r *http.Request) (string, error)) *LoopbackCallback {
	lc := &LoopbackCallback{
		valueCh: make(chan string, 1),
		errCh:   make(chan error, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		value, err := handle(w, r)
		if err != nil {
			lc.errCh <- err
			return
		}
		lc.valueCh <- value
	})
	lc.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = lc.srv.Serve(listener) }()
	return lc
}

// Wait blocks for the first callback request's outcome, honoring ctx
// cancellation and timeout (<= 0 defaults to defaultLoopbackTimeout).
// The server is shut down cleanly on every exit path (success, handle
// error, timeout, or cancellation) — callers don't need to manage its
// lifecycle beyond closing the listener passed to
// StartLoopbackCallback.
func (lc *LoopbackCallback) Wait(ctx context.Context, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = defaultLoopbackTimeout
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = lc.srv.Shutdown(shutCtx)
	}()

	select {
	case v := <-lc.valueCh:
		return v, nil
	case err := <-lc.errCh:
		return "", err
	case <-time.After(timeout):
		return "", fmt.Errorf("login timed out after %s", timeout)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// OpenBrowser opens the OS-appropriate browser at rawURL. On Linux it
// first checks for a headless session (no DISPLAY/WAYLAND_DISPLAY,
// the common SSH/container/CI signature) and returns an error instead
// of attempting xdg-open, which would otherwise hang or fail
// confusingly with no window system to talk to.
//
// The launch itself is non-blocking (exec.Command(...).Start(), not
// .Run()) — it returns as soon as the OS process starts, without
// waiting for the browser to load the page or the user to complete
// login. Callers relying on StartLoopbackCallback's ordering guarantee
// depend on this: call StartLoopbackCallback first, then OpenBrowser,
// then Wait.
//
// A package-level var (not a plain func) so callers — chiefly this
// package's own tests, which can't exercise a real exec.Command in
// headless CI — can swap in a mock that drives the loopback callback
// directly instead of actually launching a browser.
var OpenBrowser = func(rawURL string) error {
	if isHeadlessSession() {
		return errors.New("no display detected (headless session); open the URL manually")
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start()
	case "linux":
		return exec.Command("xdg-open", rawURL).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	}
	return errors.New("unsupported platform; copy the URL above manually")
}

// isHeadlessSession reports whether this process is likely running
// without a display (SSH session, container, CI runner) — checked
// only on Linux, where DISPLAY/WAYLAND_DISPLAY being unset is a
// reliable signal. Other platforms don't have an equivalent
// environment-variable convention, so this always reports false
// there and lets the OS-specific opener attempt (and fail on its own
// terms) instead.
func isHeadlessSession() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	return os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
}
