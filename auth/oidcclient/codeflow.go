package oidcclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// RunCodeFlow performs an OAuth2 authorization-code flow with PKCE,
// using a loopback http.Server on a chosen (or auto-picked) port to
// capture the redirect. The /token endpoint exchange returns the
// access + refresh + id_token triple.
//
// Standard public-client pattern: no client secret. S256 PKCE binds
// the code to this specific browser session so the redirect URL alone
// can't be replayed by an attacker who later captures it.
//
// stderr receives the human-readable "open this URL" prompt; pass
// io.Discard to silence it.
func RunCodeFlow(ctx context.Context, issuer, clientID string, port int, stderr io.Writer) (*Tokens, error) {
	verifier, err := randomURLSafe(32)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state, err := randomURLSafe(24)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("loopback listen: %w", err)
	}
	defer listener.Close()
	redirectURI := fmt.Sprintf("http://%s/callback", listener.Addr().String())

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			errCh <- fmt.Errorf("auth server returned error: %s (%s)", e, q.Get("error_description"))
			http.Error(w, "Auth error: "+e, http.StatusBadRequest)
			return
		}
		if q.Get("state") != state {
			errCh <- errors.New("state mismatch (possible CSRF)")
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if code == "" {
			errCh <- errors.New("authorization server returned no code")
			http.Error(w, "no code", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, "<html><body><h2>Login successful</h2><p>You may close this tab.</p></body></html>")
		codeCh <- code
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	authURL := BuildAuthorizeURL(issuer, clientID, redirectURI, state, challenge)
	if stderr != nil {
		fmt.Fprintln(stderr, "Opening browser for OIDC login. If it doesn't open, paste this URL:")
		fmt.Fprintln(stderr, "  ", authURL)
	}
	_ = openBrowser(authURL)

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, errors.New("login timed out after 5 minutes")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return exchangeCode(ctx, issuer, clientID, redirectURI, code, verifier)
}

// BuildAuthorizeURL constructs the /authorize URL for the code flow.
// Exported so a caller (or test) can verify the exact wire shape
// without doing IO.
func BuildAuthorizeURL(issuer, clientID, redirectURI, state, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid email profile offline_access")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return strings.TrimRight(issuer, "/") + "/authorize?" + q.Encode()
}

func exchangeCode(ctx context.Context, issuer, clientID, redirectURI, code, verifier string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	return PostToken(ctx, issuer, form)
}

func openBrowser(rawURL string) error {
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

// randomURLSafe returns n random bytes encoded as base64url (RFC 4648
// §5, no padding). Used for PKCE verifiers and CSRF state values.
func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
