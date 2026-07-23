package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"golang.org/x/oauth2"

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
// — nothing more. Everything past authentication is owned by the
// [SessionIssuer] the caller builds and injects into [NewAuthenticator];
// this package has no notion of sessions, cookie scopes, or group
// membership. It builds on a [TokenVerifier] for ID-token validation and
// base/auth/oidcclient for the token exchange.
type AuthenticatorConfig struct {
	Issuer       string        // IdP issuer URL (e.g. https://id.example.com)
	ClientID     string        // registered OIDC client_id (= ID-token audience)
	ClientSecret string        // confidential-client secret; empty ⇒ public client (PKCE only)
	RedirectURL  string        // absolute callback URL registered with the IdP
	Verifier     TokenVerifier // validates the returned ID token (audience = ClientID)
	Scopes       string        // authorize scopes; "" ⇒ "openid email profile groups"

	// CallbackPath is the route [Authenticator.CallbackHandler] is mounted
	// at, as the injected [SessionIssuer] sees r.URL.Path (e.g. a
	// [session.Manager]'s Gate). It MUST be exempt from that gate — a
	// [session.Manager]'s ExemptPaths (or its LoginPath/LogoutPath, though
	// that would be unusual) — [NewAuthenticator] verifies this via
	// [SessionIssuer.IsExempt] and fails construction otherwise, since an
	// unexempted callback would be redirected to login before the flow
	// could ever complete. "" ⇒ /auth/callback.
	CallbackPath string

	// FlowCookie is the sealed cookie [Authenticator] uses to carry
	// per-login CSRF/PKCE state (state/nonce/PKCE verifier/return_to/extra)
	// across the redirect round-trip, before any session exists. It is
	// independent of however the caller ultimately persists the
	// authenticated session (a sealed cookie via [session.Manager], a
	// server-side token-table row, or anything else) — required so
	// [NewAuthenticator] fails fast rather than defaulting to an
	// unconfigured cookie. A caller using [session.Manager] for its
	// session typically passes sess.SiblingCookie("flow") here, so the
	// flow cookie shares that Manager's key, path scope, and clock under
	// its own name.
	FlowCookie sealedcookie.Cookie

	// EnrichSession, if set, is called by [DefaultCompleter]'s default
	// completion path after the ID token verifies and the base
	// [session.Session] is built (via [DefaultCompleter.NewSession]),
	// before it is sealed into the cookie. Populate Session.Extra (or
	// adjust Expiry) from the claims or your own store — the ctx is the
	// callback request's, so a login-time lookup (tenant, role snapshot,
	// …) is fine. A returned error ABORTS the login with a 500: fail
	// closed rather than mint a session missing authorization data. Nil
	// ⇒ the base session is sealed as-is. Ignored entirely when the
	// injected [SessionIssuer] implements [CompletionOverride] instead —
	// that path owns 100% of its own completion logic.
	EnrichSession func(ctx context.Context, claims *Claims, sess *session.Session) error
}

// SessionIssuer is the minimal contract every [Authenticator] caller
// supplies: return_to sanitisation, callback-path exemption (checked at
// construction), and a logging sink. *[session.Manager] satisfies this
// verbatim. A SessionIssuer must additionally implement [DefaultCompleter]
// or [CompletionOverride] (or both) so the flow has a way to actually
// complete a verified login — [NewAuthenticator] enforces this.
type SessionIssuer interface {
	// SafeReturnTo confines an untrusted "return to this path after
	// login" value; see [session.Manager.SafeReturnTo].
	SafeReturnTo(path string) string
	// IsExempt reports whether path is exempt from this issuer's access
	// gate, if any; see [session.Manager.IsExempt].
	IsExempt(path string) bool
	// Log returns the logging sink used for warnings and info lines
	// throughout the flow; see [session.Manager.Log].
	Log() *slog.Logger
}

// DefaultCompleter is the "mint a session, persist it, redirect to
// ReturnTo" completion [Authenticator.CallbackHandler] uses when the
// injected [SessionIssuer] does not implement [CompletionOverride].
// *[session.Manager] satisfies this verbatim via NewSession/IssueSession —
// this is today's (and ca portal's) behavior, unchanged.
type DefaultCompleter interface {
	// NewSession returns a fresh base session shape; see
	// [session.Manager.NewSession].
	NewSession() (session.Session, error)
	// IssueSession seals sess into the session cookie; see
	// [session.Manager.IssueSession].
	IssueSession(w http.ResponseWriter, r *http.Request, sess session.Session) error
}

// CompletedFlow carries the sanitised ReturnTo plus the opaque Extra value
// the caller supplied to [Authenticator.Begin] at login time, handed back
// verbatim to [CompletionOverride.CompleteLogin] once the ID token and
// nonce have verified.
type CompletedFlow struct {
	ReturnTo string
	Extra    string
}

// CompletionOverride lets a [SessionIssuer] take full control of the HTTP
// response for a verified login, instead of [DefaultCompleter]'s default
// mint-session-and-redirect behavior. Implement it when a single callback
// endpoint must serve more than one completion shape from the same OIDC
// flow — e.g. JSON for a plain API caller, a redirect carrying an opaque
// credential for a CLI loopback flow, and a cookie + redirect for a
// browser session, selected by the caller's own Extra convention.
//
// When a SessionIssuer implements both CompletionOverride and
// [DefaultCompleter], CompletionOverride takes precedence — a SessionIssuer
// implementing only DefaultCompleter always gets the default path.
type CompletionOverride interface {
	// CompleteLogin receives the verified claims and the parsed flow, and
	// MUST fully write the HTTP response (redirect, JSON body, cookie —
	// whatever fits). Returning an error causes [Authenticator] to log it
	// and respond 500; a nil error means the response was already
	// written and CallbackHandler does nothing further.
	CompleteLogin(w http.ResponseWriter, r *http.Request, claims *Claims, flow CompletedFlow) error
}

// Authenticator runs the browser OIDC Authorization-Code + PKCE flow and
// nothing else: [Authenticator.LoginHandler] (or [Authenticator.Begin])
// starts it, [Authenticator.CallbackHandler] completes it via the
// [SessionIssuer] it was constructed with — either its [DefaultCompleter]
// (mint a session, redirect to ReturnTo) or its [CompletionOverride] (full
// response control) implementation. Build with [NewAuthenticator]. For the
// session cookie, the access gate, CSRF tokens, and logout of a
// [session.Manager]-backed issuer, use the injected *session.Manager
// directly — Authenticator does not wrap or re-expose it.
type Authenticator struct {
	cfg  AuthenticatorConfig
	sess SessionIssuer
	// flow is the login-flow cookie (state/nonce/PKCE verifier/return_to/
	// extra) — a distinct, short-lived payload carrying per-login
	// CSRF/PKCE state across the redirect round-trip, before any session
	// exists. Set from [AuthenticatorConfig.FlowCookie] at construction;
	// independent of however the caller later persists the session.
	flow sealedcookie.Cookie
}

// NewAuthenticator validates cfg, verifies sess exempts CallbackPath from
// its gate, and returns an Authenticator. Issuer, ClientID, RedirectURL,
// Verifier, FlowCookie, and sess are required. sess must additionally
// implement [DefaultCompleter] or [CompletionOverride] — a SessionIssuer
// that implements neither could never complete a login, so construction
// fails rather than deferring that discovery to the first callback.
func NewAuthenticator(cfg AuthenticatorConfig, sess SessionIssuer) (*Authenticator, error) {
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("oidc: issuer is required")
	case cfg.ClientID == "":
		return nil, errors.New("oidc: client id is required")
	case cfg.RedirectURL == "":
		return nil, errors.New("oidc: redirect url is required")
	case cfg.Verifier == nil:
		return nil, errors.New("oidc: verifier is required")
	case len(cfg.FlowCookie.Key) == 0:
		return nil, errors.New("oidc: flow cookie is required")
	case isNilSessionIssuer(sess):
		return nil, errors.New("oidc: session issuer is required")
	}
	if cfg.Scopes == "" {
		cfg.Scopes = defaultScopes
	}
	if cfg.CallbackPath == "" {
		cfg.CallbackPath = defaultCallbackPath
	}
	if !sess.IsExempt(cfg.CallbackPath) {
		return nil, fmt.Errorf("oidc: CallbackPath %q must be exempt on the session issuer's gate, or the OIDC callback will be redirected to login before it can complete", cfg.CallbackPath)
	}
	if _, ok := sess.(CompletionOverride); !ok {
		if _, ok := sess.(DefaultCompleter); !ok {
			return nil, errors.New("oidc: session issuer must implement DefaultCompleter or CompletionOverride")
		}
	}
	return &Authenticator{
		cfg:  cfg,
		sess: sess,
		flow: cfg.FlowCookie,
	}, nil
}

// oidcFlow is the per-login CSRF/PKCE state sealed into the short-lived flow
// cookie between the authorize redirect and the callback.
type oidcFlow struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"` // PKCE code_verifier
	ReturnTo string `json:"return_to"`
	// Extra is an opaque, caller-supplied value round-tripped through the
	// sealed flow cookie — see [Authenticator.Begin] and [CompletedFlow].
	// Unused by [DefaultCompleter]'s default completion path.
	Extra string `json:"extra,omitempty"`
}

// LoginHandler starts the Authorization-Code flow via [Authenticator.Begin]
// with an empty Extra, then redirects the browser to the returned
// authorize URL. Use [Authenticator.Begin] directly when a caller needs to
// supply Extra or control the response itself (e.g. returning the
// authorize URL as JSON instead of redirecting).
func (a *Authenticator) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authURL, err := a.Begin(w, r, "")
		if err != nil {
			http.Error(w, "login init failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusSeeOther)
	}
}

// Begin mints state, nonce, and a PKCE verifier, seals them into the flow
// cookie together with a sanitised return_to (from the "return_to" query
// parameter) and extra, and returns the IdP authorize URL to redirect or
// respond with. It writes only the flow cookie — the caller decides how to
// deliver authURL (redirect, JSON body, …).
func (a *Authenticator) Begin(w http.ResponseWriter, r *http.Request, extra string) (authURL string, err error) {
	state, err1 := randB64(24)
	nonce, err2 := randB64(24)
	verifier, err3 := randB64(32)
	if err1 != nil || err2 != nil || err3 != nil {
		return "", errors.New("oidc: generate flow entropy")
	}
	flow := oidcFlow{
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
		ReturnTo: a.sess.SafeReturnTo(r.URL.Query().Get("return_to")),
		Extra:    extra,
	}
	if err := a.flow.Set(w, r, flow, flowTTL); err != nil {
		return "", err
	}

	ep, err := a.endpoint(r.Context())
	if err != nil {
		return "", fmt.Errorf("oidc: resolve endpoint: %w", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return a.authorizeURL(ep, state, nonce, challenge), nil
}

// authorizeURL builds the IdP /authorize redirect for the code flow, from
// the endpoint resolved via [Authenticator.endpoint].
func (a *Authenticator) authorizeURL(ep oauth2.Endpoint, state, nonce, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", a.cfg.ClientID)
	q.Set("redirect_uri", a.cfg.RedirectURL)
	q.Set("scope", a.cfg.Scopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return ep.AuthURL + "?" + q.Encode()
}

// endpointResolver is implemented by verifiers that can report the IdP's
// discovered OAuth2 endpoints, deferring discovery to this call if it
// hasn't happened yet — [LazyVerifier.Endpoint] matches this shape
// directly.
type endpointResolver interface {
	Endpoint(ctx context.Context) (oauth2.Endpoint, error)
}

// syncEndpointResolver is the shape [HTTPVerifier.Endpoint] exposes:
// discovery already happened at construction, so no context or error is
// needed.
type syncEndpointResolver interface {
	Endpoint() oauth2.Endpoint
}

// endpoint resolves the IdP's authorize/token endpoints from the configured
// Verifier when it exposes them (real OIDC discovery — required for
// interop with any IdP whose paths don't follow the tokyo3-auth
// convention, e.g. Google/Okta/Auth0). Falls back to the hardcoded
// {issuer}/authorize + {issuer}/token convention when the Verifier exposes
// neither shape (e.g. a test stub), preserving prior behavior exactly for
// those callers. A discovery failure from an endpointResolver is returned
// rather than silently falling back — masking a genuine IdP-unreachable
// error behind a guessed URL would trade a clear failure for a confusing
// one.
func (a *Authenticator) endpoint(ctx context.Context) (oauth2.Endpoint, error) {
	switch v := a.cfg.Verifier.(type) {
	case endpointResolver:
		return v.Endpoint(ctx)
	case syncEndpointResolver:
		return v.Endpoint(), nil
	default:
		issuer := strings.TrimRight(a.cfg.Issuer, "/")
		return oauth2.Endpoint{AuthURL: issuer + "/authorize", TokenURL: issuer + "/token"}, nil
	}
}

// CallbackHandler completes the flow: it validates state against the flow
// cookie, exchanges the code for tokens, verifies the ID token and its
// nonce, then completes the login via the injected [SessionIssuer]'s
// [CompletionOverride] (if implemented) or its [DefaultCompleter]
// otherwise.
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
		ep, err := a.endpoint(r.Context())
		if err != nil {
			a.sess.Log().Warn("oidc: resolve endpoint failed", "err", err)
			http.Error(w, "token exchange failed", http.StatusBadGateway)
			return
		}
		form.Set("code_verifier", flow.Verifier)
		tokens, err := oidcclient.PostTokenAt(r.Context(), ep.TokenURL, form)
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

		if oc, ok := a.sess.(CompletionOverride); ok {
			if err := oc.CompleteLogin(w, r, claims, CompletedFlow{ReturnTo: flow.ReturnTo, Extra: flow.Extra}); err != nil {
				a.sess.Log().Error("oidc: complete login failed", "email", claims.Email, "err", err)
				http.Error(w, "session init failed", http.StatusInternalServerError)
			}
			return
		}

		// dc is guaranteed present by NewAuthenticator's construction-time
		// validation when CompletionOverride isn't implemented.
		dc := a.sess.(DefaultCompleter)
		sess, err := dc.NewSession()
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
		if err := dc.IssueSession(w, r, sess); err != nil {
			http.Error(w, "session init failed", http.StatusInternalServerError)
			return
		}
		a.sess.Log().Info("oidc: login", "email", claims.Email, "groups", claims.Groups)
		http.Redirect(w, r, flow.ReturnTo, http.StatusSeeOther)
	}
}

// isNilSessionIssuer reports whether sess is nil, guarding against the
// classic Go footgun where a caller passes a nil pointer of a concrete
// type (e.g. a nil *session.Manager) directly as the SessionIssuer
// argument: that produces a non-nil interface value wrapping a nil
// pointer, which "sess == nil" alone would not catch, leading to a nil-
// pointer panic on the first method call instead of a clear construction
// error.
func isNilSessionIssuer(sess SessionIssuer) bool {
	if sess == nil {
		return true
	}
	v := reflect.ValueOf(sess)
	switch v.Kind() { //nolint:exhaustive // only the nilable kinds matter here
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
		return v.IsNil()
	default:
		return false
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
