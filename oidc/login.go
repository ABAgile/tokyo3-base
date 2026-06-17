package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/auth/oidcclient"
	"github.com/abagile/tokyo3-base/crypto"
)

const (
	defaultSessionTTL   = 8 * time.Hour
	flowTTL             = 10 * time.Minute
	defaultScopes       = "openid email profile groups"
	defaultLoginPath    = "/auth/login"
	defaultCallbackPath = "/auth/callback"
	defaultLogoutPath   = "/auth/logout"
)

// Session is the authenticated identity sealed into the session cookie and
// injected into the request context by [Authenticator.Gate]. Read it with
// [SessionFromContext].
type Session struct {
	Subject string    `json:"sub"`
	Email   string    `json:"email"`
	Name    string    `json:"name"`
	Groups  []string  `json:"groups"`
	Expiry  time.Time `json:"exp"`
}

// AuthenticatorConfig wires native browser-based OIDC login for an admin
// portal: an Authorization-Code + PKCE flow against the IdP, an encrypted
// session cookie, and an optional admin-group gate. It builds on a
// [TokenVerifier] for ID-token validation and base/auth/oidcclient for the
// token exchange, owning only the browser glue.
type AuthenticatorConfig struct {
	Issuer       string        // IdP issuer URL (e.g. https://id.example.com)
	ClientID     string        // registered OIDC client_id (= ID-token audience)
	ClientSecret string        // confidential-client secret; empty ⇒ public client (PKCE only)
	RedirectURL  string        // absolute callback URL registered with the IdP
	AdminGroup   string        // required group claim for access; "" ⇒ any authenticated user
	Verifier     TokenVerifier // validates the returned ID token (audience = ClientID)
	SessionKey   []byte        // 32-byte key sealing the session + flow cookies (AES-256-GCM)
	SessionTTL   time.Duration // session lifetime; 0 ⇒ 8h
	Scopes       string        // authorize scopes; "" ⇒ "openid email profile groups"

	// CookiePrefix names the cookies — <prefix>_session and <prefix>_flow.
	// Required, so multiple apps on one host don't collide.
	CookiePrefix string
	// CookiePath scopes the cookies (e.g. "/portal/"). "" ⇒ "/".
	CookiePath string

	// LoginPath, CallbackPath, LogoutPath are the routes — as [Authenticator.Gate]
	// sees r.URL.Path — the handlers are mounted at. The Gate exempts them and
	// redirects unauthenticated GETs to LoginPath. Defaults: /auth/login,
	// /auth/callback, /auth/logout.
	LoginPath, CallbackPath, LogoutPath string
	// ExemptPaths are extra paths the Gate lets through unauthenticated
	// (e.g. "/healthz").
	ExemptPaths []string

	Now func() time.Time // injectable clock; nil ⇒ time.Now
	Log *slog.Logger     // nil ⇒ slog.Default
}

// Authenticator runs the browser OIDC login flow and gates portal routes
// behind the resulting session. Build with [NewAuthenticator]; mount
// [Authenticator.LoginHandler]/CallbackHandler/LogoutHandler at the configured
// paths and wrap the protected mux with [Authenticator.Gate].
type Authenticator struct {
	cfg           AuthenticatorConfig
	sessionCookie string
	flowCookie    string
	exempt        map[string]struct{}
}

// NewAuthenticator validates cfg and returns an Authenticator. Issuer,
// ClientID, RedirectURL, Verifier, SessionKey, and CookiePrefix are required.
func NewAuthenticator(cfg AuthenticatorConfig) (*Authenticator, error) {
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("oidc: issuer is required")
	case cfg.ClientID == "":
		return nil, errors.New("oidc: client id is required")
	case cfg.RedirectURL == "":
		return nil, errors.New("oidc: redirect url is required")
	case cfg.Verifier == nil:
		return nil, errors.New("oidc: verifier is required")
	case len(cfg.SessionKey) == 0:
		return nil, errors.New("oidc: session key is required")
	case cfg.CookiePrefix == "":
		return nil, errors.New("oidc: cookie prefix is required")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if cfg.Scopes == "" {
		cfg.Scopes = defaultScopes
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = "/"
	}
	if cfg.LoginPath == "" {
		cfg.LoginPath = defaultLoginPath
	}
	if cfg.CallbackPath == "" {
		cfg.CallbackPath = defaultCallbackPath
	}
	if cfg.LogoutPath == "" {
		cfg.LogoutPath = defaultLogoutPath
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	a := &Authenticator{
		cfg:           cfg,
		sessionCookie: cfg.CookiePrefix + "_session",
		flowCookie:    cfg.CookiePrefix + "_flow",
		exempt:        make(map[string]struct{}),
	}
	for _, p := range append([]string{cfg.LoginPath, cfg.CallbackPath, cfg.LogoutPath}, cfg.ExemptPaths...) {
		a.exempt[p] = struct{}{}
	}
	return a, nil
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
		flow := oidcFlow{State: state, Nonce: nonce, Verifier: verifier, ReturnTo: safeReturnTo(r.URL.Query().Get("return_to"))}
		sealed, err := a.seal(flow)
		if err != nil {
			http.Error(w, "login init failed", http.StatusInternalServerError)
			return
		}
		a.setCookie(w, r, a.flowCookie, sealed, flowTTL)

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
// and establishes the session cookie.
func (a *Authenticator) CallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var flow oidcFlow
		c, err := r.Cookie(a.flowCookie)
		if err != nil || a.open(c.Value, &flow) != nil {
			http.Error(w, "login session expired — start again", http.StatusBadRequest)
			return
		}
		a.clearCookie(w, r, a.flowCookie)

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
			a.cfg.Log.Warn("oidc: token exchange failed", "err", err)
			http.Error(w, "token exchange failed", http.StatusBadGateway)
			return
		}

		claims, err := a.cfg.Verifier.Verify(r.Context(), tokens.IDToken)
		if err != nil {
			a.cfg.Log.Warn("oidc: id_token verify failed", "err", err)
			http.Error(w, "invalid ID token", http.StatusUnauthorized)
			return
		}
		if claims.Nonce != flow.Nonce {
			http.Error(w, "nonce mismatch — possible token replay; start again", http.StatusBadRequest)
			return
		}

		sess := Session{
			Subject: claims.Subject,
			Email:   claims.Email,
			Name:    claims.Name,
			Groups:  claims.Groups,
			Expiry:  a.cfg.Now().Add(a.cfg.SessionTTL),
		}
		sealed, err := a.seal(sess)
		if err != nil {
			http.Error(w, "session init failed", http.StatusInternalServerError)
			return
		}
		a.setCookie(w, r, a.sessionCookie, sealed, a.cfg.SessionTTL)
		a.cfg.Log.Info("oidc: login", "email", claims.Email, "groups", claims.Groups)
		http.Redirect(w, r, flow.ReturnTo, http.StatusSeeOther)
	}
}

// LogoutHandler clears the session cookie and redirects to the login route.
func (a *Authenticator) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.clearCookie(w, r, a.sessionCookie)
		http.Redirect(w, r, a.cfg.LoginPath, http.StatusSeeOther)
	}
}

// Gate wraps next behind a valid session and, when AdminGroup is set,
// membership in it. The configured login/callback/logout routes and any
// ExemptPaths are let through. A GET without a session redirects to LoginPath
// (carrying return_to); a non-GET answers 401 (its body can't survive a
// redirect round-trip). On success the [Session] is injected into the request
// context for [SessionFromContext].
func (a *Authenticator) Gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.exempt[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		sess, ok := a.readSession(r)
		if !ok {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, a.cfg.LoginPath+"?return_to="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
				return
			}
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if g := a.cfg.AdminGroup; g != "" && !slices.Contains(sess.Groups, g) {
			http.Error(w, "forbidden: requires membership in "+g, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sess)))
	})
}

// readSession returns the live (unexpired) session from the request cookie.
func (a *Authenticator) readSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie(a.sessionCookie)
	if err != nil {
		return Session{}, false
	}
	var sess Session
	if err := a.open(c.Value, &sess); err != nil {
		return Session{}, false
	}
	if a.cfg.Now().After(sess.Expiry) {
		return Session{}, false
	}
	return sess, true
}

type ctxKey int

const sessionCtxKey ctxKey = 0

// SessionFromContext returns the session [Authenticator.Gate] injected, if any.
func SessionFromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionCtxKey).(Session)
	return s, ok
}

// ── cookie sealing ───────────────────────────────────────────────────────────

func (a *Authenticator) seal(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sealed, err := crypto.Seal(a.cfg.SessionKey, b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (a *Authenticator) open(val string, dst any) error {
	raw, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil {
		return err
	}
	pt, err := crypto.Open(a.cfg.SessionKey, raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(pt, dst)
}

func (a *Authenticator) setCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     a.cfg.CookiePath,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  a.cfg.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
	})
}

func (a *Authenticator) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     a.cfg.CookiePath,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// randB64 returns n random bytes as base64url (RFC 4648 §5, no padding).
func randB64(n int) (string, error) {
	b, err := crypto.RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// safeReturnTo confines the post-login redirect to a local absolute path, so a
// crafted return_to can't bounce the browser to an attacker origin.
func safeReturnTo(p string) string {
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") {
		return p
	}
	return "/"
}
