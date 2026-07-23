package oidcclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	listener, redirectURI, err := LoopbackListener(port, "/callback")
	if err != nil {
		return nil, err
	}
	defer listener.Close()

	// Start serving before opening the browser: the redirect must land
	// on a listener that's already accepting requests.
	lc := StartLoopbackCallback(listener, "/callback", func(w http.ResponseWriter, r *http.Request) (string, error) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			http.Error(w, "Auth error: "+e, http.StatusBadRequest)
			return "", fmt.Errorf("auth server returned error: %s (%s)", e, q.Get("error_description"))
		}
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return "", errors.New("state mismatch (possible CSRF)")
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "no code", http.StatusBadRequest)
			return "", errors.New("authorization server returned no code")
		}
		fmt.Fprintln(w, "<html><body><h2>Login successful</h2><p>You may close this tab.</p></body></html>")
		return code, nil
	})

	// Discover the real /authorize + /token endpoints when the issuer
	// exposes a discovery document; falls back to the tokyo3-auth path
	// convention (the exact pre-discovery behavior) otherwise.
	ep := discoverEndpoints(ctx, issuer)

	authURL := buildAuthorizeURLAt(ep.AuthorizationEndpoint, clientID, redirectURI, state, challenge)
	if stderr != nil {
		fmt.Fprintln(stderr, "Opening browser for OIDC login. If it doesn't open, paste this URL:")
		fmt.Fprintln(stderr, "  ", authURL)
	}
	_ = OpenBrowser(authURL)

	code, err := lc.Wait(ctx, 0)
	if err != nil {
		return nil, err
	}
	return exchangeCodeAt(ctx, ep.TokenEndpoint, clientID, redirectURI, code, verifier)
}

// BuildAuthorizeURL constructs the /authorize URL for the code flow
// using the tokyo3-auth path convention ({issuer}/authorize). Exported
// so a caller (or test) can verify the exact wire shape without doing
// IO. RunCodeFlow itself uses the issuer's discovered authorization
// endpoint when available (see discoverEndpoints) and only falls back
// to this convention when discovery is unavailable.
func BuildAuthorizeURL(issuer, clientID, redirectURI, state, challenge string) string {
	return buildAuthorizeURLAt(conventionEndpoints(issuer).AuthorizationEndpoint, clientID, redirectURI, state, challenge)
}

func buildAuthorizeURLAt(authEndpoint, clientID, redirectURI, state, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid email profile offline_access")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return authEndpoint + "?" + q.Encode()
}

func exchangeCodeAt(ctx context.Context, tokenEndpoint, clientID, redirectURI, code, verifier string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	return PostTokenAt(ctx, tokenEndpoint, form)
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
