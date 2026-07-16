package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/auth/oidcclient"
	"github.com/abagile/tokyo3-base/crypto"
	"github.com/abagile/tokyo3-base/sealedcookie"
	"github.com/abagile/tokyo3-base/session"
)

const (
	flowTTL             = 10 * time.Minute
	defaultScopes       = "openid email profile groups"
	defaultCallbackPath = "/auth/callback"
)

// AuthenticatorConfig wires the OIDC Authorization-Code + PKCE flow itself
// — nothing more. Everything past authentication (the session cookie, the
// access gate, CSRF tokens, Origin verification) is a [session.Manager]
// the caller builds and injects into [NewAuthenticator]; this package has
// no notion of sessions, cookies scopes, or group membership. It builds on
// a [TokenVerifier] for ID-token validation and base/auth/oidcclient for
// the token exchange.
type AuthenticatorConfig struct {
	Issuer       string        // IdP issuer URL (e.g. https://id.example.com)
	ClientID     string        // registered OIDC client_id (= ID-token audience)
	ClientSecret string        // confidential-client secret; empty ⇒ public client (PKCE only)
	RedirectURL  string        // absolute callback URL registered with the IdP
	Verifier     TokenVerifier // validates the returned ID token (audience = ClientID)
	Scopes       string        // authorize scopes; "" ⇒ "openid email profile groups"

	// CallbackPath is the route [Authenticator.CallbackHandler] is mounted
	// at, as the injected [session.Manager]'s Gate sees r.URL.Path. It
	// MUST be present in that Manager's ExemptPaths (or be its LoginPath /
	// LogoutPath, though that would be unusual) — [NewAuthenticator]
	// verifies this and fails construction otherwise, since an unexempted
	// callback would be redirected to login before the flow could ever
	// complete. "" ⇒ /auth/callback.
	CallbackPath string

	// EnrichSession, if set, is called by the callback handler after the
	// ID token verifies and the base [session.Session] is built (via
	// session.Manager.NewSession), before it is sealed into the cookie.
	// Populate Session.Extra (or adjust Expiry) from the claims or your
	// own store — the ctx is the callback request's, so a login-time
	// lookup (tenant, role snapshot, …) is fine. A returned error ABORTS
	// the login with a 500: fail closed rather than mint a session missing
	// authorization data. Nil ⇒ the base session is sealed as-is.
	EnrichSession func(ctx context.Context, claims *Claims, sess *session.Session) error
}

// Authenticator runs the browser OIDC Authorization-Code + PKCE flow and
// nothing else: [Authenticator.LoginHandler] starts it,
// [Authenticator.CallbackHandler] completes it by minting a session on the
// [session.Manager] it was constructed with. Build with [NewAuthenticator].
// For the session cookie, the access gate, CSRF tokens, and logout, use the
// injected *session.Manager directly — Authenticator does not wrap or
// re-expose it.
type Authenticator struct {
	cfg  AuthenticatorConfig
	sess *session.Manager
	// flow is the login-flow cookie (state/nonce/PKCE verifier/return_to)
	// — a distinct, short-lived payload built via [session.Manager.SiblingCookie],
	// so it shares the session cookie's key, path scope, and clock, under
	// its own name and TTL. It does not go through session.Manager, which
	// only knows about [session.Session].
	flow sealedcookie.Cookie
}

// NewAuthenticator validates cfg, verifies sess exempts CallbackPath from
// its gate, and returns an Authenticator. Issuer, ClientID, RedirectURL,
// Verifier, and sess are required. The flow cookie's key, path, and clock,
// and all logging, are derived from sess — see [session.Manager.SiblingCookie]
// and [session.Manager.Log] — so this config carries no session/cookie
// mechanics of its own to keep in sync with the injected Manager's.
func NewAuthenticator(cfg AuthenticatorConfig, sess *session.Manager) (*Authenticator, error) {
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("oidc: issuer is required")
	case cfg.ClientID == "":
		return nil, errors.New("oidc: client id is required")
	case cfg.RedirectURL == "":
		return nil, errors.New("oidc: redirect url is required")
	case cfg.Verifier == nil:
		return nil, errors.New("oidc: verifier is required")
	case sess == nil:
		return nil, errors.New("oidc: session manager is required")
	}
	if cfg.Scopes == "" {
		cfg.Scopes = defaultScopes
	}
	if cfg.CallbackPath == "" {
		cfg.CallbackPath = defaultCallbackPath
	}
	if !sess.IsExempt(cfg.CallbackPath) {
		return nil, fmt.Errorf("oidc: CallbackPath %q must be exempt on the session.Manager's Gate, or the OIDC callback will be redirected to login before it can complete", cfg.CallbackPath)
	}
	return &Authenticator{
		cfg:  cfg,
		sess: sess,
		flow: sess.SiblingCookie("flow"),
	}, nil
}

// oidcFlow is the per-login CSRF/PKCE state sealed into the short-lived flow
// cookie between the authorize redirect and the callback.
type oidcFlow struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"` // PKCE code_verifier
	ReturnTo string `json:"return_to"`
}

// LoginHandler starts the Authorization-Code flow: it mints state, nonce, and
// a PKCE verifier, seals them into the flow cookie, and redirects to the IdP's
// authorize endpoint.
func (a *Authenticator) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err1 := randB64(24)
		nonce, err2 := randB64(24)
		verifier, err3 := randB64(32)
		if err1 != nil || err2 != nil || err3 != nil {
			http.Error(w, "login init failed", http.StatusInternalServerError)
			return
		}
		flow := oidcFlow{State: state, Nonce: nonce, Verifier: verifier, ReturnTo: a.sess.SafeReturnTo(r.URL.Query().Get("return_to"))}
		if err := a.flow.Set(w, r, flow, flowTTL); err != nil {
			http.Error(w, "login init failed", http.StatusInternalServerError)
			return
		}

		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		http.Redirect(w, r, a.authorizeURL(state, nonce, challenge), http.StatusSeeOther)
	}
}

// authorizeURL builds the IdP /authorize redirect for the code flow.
func (a *Authenticator) authorizeURL(state, nonce, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", a.cfg.ClientID)
	q.Set("redirect_uri", a.cfg.RedirectURL)
	q.Set("scope", a.cfg.Scopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return strings.TrimRight(a.cfg.Issuer, "/") + "/authorize?" + q.Encode()
}

// CallbackHandler completes the flow: it validates state against the flow
// cookie, exchanges the code for tokens, verifies the ID token and its nonce,
// and establishes the session cookie via the injected session.Manager.
func (a *Authenticator) CallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var flow oidcFlow
		if err := a.flow.Read(r, &flow); err != nil {
			http.Error(w, "login session expired — start again", http.StatusBadRequest)
			return
		}
		a.flow.Clear(w, r)

		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			http.Error(w, "IdP returned an error: "+e, http.StatusUnauthorized)
			return
		}
		if q.Get("state") != flow.State || flow.State == "" {
			http.Error(w, "state mismatch — possible CSRF; start again", http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "no authorization code", http.StatusBadRequest)
			return
		}

		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", a.cfg.RedirectURL)
		form.Set("client_id", a.cfg.ClientID)
		if a.cfg.ClientSecret != "" {
			form.Set("client_secret", a.cfg.ClientSecret)
		}
		form.Set("code_verifier", flow.Verifier)
		tokens, err := oidcclient.PostToken(r.Context(), a.cfg.Issuer, form)
		if err != nil {
			a.sess.Log().Warn("oidc: token exchange failed", "err", err)
			http.Error(w, "token exchange failed", http.StatusBadGateway)
			return
		}

		claims, err := a.cfg.Verifier.Verify(r.Context(), tokens.IDToken)
		if err != nil {
			a.sess.Log().Warn("oidc: id_token verify failed", "err", err)
			http.Error(w, "invalid ID token", http.StatusUnauthorized)
			return
		}
		if claims.Nonce != flow.Nonce {
			http.Error(w, "nonce mismatch — possible token replay; start again", http.StatusBadRequest)
			return
		}

		sess, err := a.sess.NewSession()
		if err != nil {
			http.Error(w, "session init failed", http.StatusInternalServerError)
			return
		}
		sess.Subject = claims.Subject
		sess.Email = claims.Email
		sess.Name = claims.Name
		sess.Groups = claims.Groups
		if a.cfg.EnrichSession != nil {
			if err := a.cfg.EnrichSession(r.Context(), claims, &sess); err != nil {
				a.sess.Log().Warn("oidc: session enrichment failed; login aborted", "email", claims.Email, "err", err)
				http.Error(w, "session init failed", http.StatusInternalServerError)
				return
			}
		}
		if err := a.sess.IssueSession(w, r, sess); err != nil {
			http.Error(w, "session init failed", http.StatusInternalServerError)
			return
		}
		a.sess.Log().Info("oidc: login", "email", claims.Email, "groups", claims.Groups)
		http.Redirect(w, r, flow.ReturnTo, http.StatusSeeOther)
	}
}

// randB64 returns n random bytes as base64url (RFC 4648 §5, no padding).
func randB64(n int) (string, error) {
	b, err := crypto.RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
