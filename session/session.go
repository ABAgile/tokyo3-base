// Package session implements a sealed-cookie browser session: an encrypted
// identity cookie, an access gate (group membership, redirect-to-login,
// optional Origin/Sec-Fetch-Site verification), and session-bound anti-CSRF
// tokens. It has no notion of HOW the identity was established — OIDC,
// SAML, a magic link, HTTP Basic followed by session issuance, whatever —
// that is the caller's job: authenticate the request some other way, build
// a [Session], and call [Manager.IssueSession]. base/oidc is the one
// consumer in this codebase today, composing a Manager underneath its
// Authorization-Code + PKCE flow.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/csrf"
	"github.com/abagile/tokyo3-base/sealedcookie"
)

const (
	defaultSessionTTL = 8 * time.Hour
	defaultLoginPath  = "/auth/login"
	defaultLogoutPath = "/auth/logout"
)

// Session is the authenticated identity sealed into the session cookie and
// injected into the request context by [Manager.Gate]. Read it with
// [SessionFromContext].
type Session struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Name    string   `json:"name"`
	Groups  []string `json:"groups"`
	// Expiry is when the session dies. Fixed at login when
	// [Config.IdleTimeout] is unset (0) — the session lasts exactly
	// SessionTTL regardless of activity. When IdleTimeout is set,
	// [Manager.Gate] slides this forward on activity, but never past
	// AbsoluteExpiry.
	Expiry time.Time `json:"exp"`
	// AbsoluteExpiry is the hard ceiling this session can never be
	// extended past regardless of idle-based renewal: set once at
	// [Manager.NewSession] to login-time + SessionTTL, and never moved
	// afterward. Equal to Expiry whenever IdleTimeout is unset (today's
	// hard-cap-only behaviour). If [AuthenticatorConfig.EnrichSession]-style
	// code adjusts Expiry at login, adjust this too if idle extension should
	// be capped relative to the new value.
	AbsoluteExpiry time.Time `json:"abs_exp"`
	// CSRFSecret seeds session-bound anti-CSRF tokens (base/csrf, via
	// [Manager.CSRFToken] / [Manager.ValidateCSRF]). Minted by
	// [Manager.NewSession] — consumers normally never touch it, but MAY
	// rotate it mid-session via [Manager.UpdateSession] (e.g. after a
	// privilege change), which invalidates all previously issued tokens.
	CSRFSecret csrf.Secret `json:"csrf,omitempty"`
	// Extra is an opaque consumer-defined payload. Marshal your own typed
	// struct into it (typically while populating the [Session] returned by
	// [Manager.NewSession], before [Manager.IssueSession]) and unmarshal it
	// where you read the session — this package never inspects it. Keep it
	// to IDs and flags: the whole sealed session must stay well under the
	// ~4 KB per-cookie browser cap, and its contents are a login-time
	// snapshot until Expiry, not live state.
	Extra json.RawMessage `json:"extra,omitempty"`
}

// Config wires a [Manager].
type Config struct {
	// RequiredGroup is the group claim required for [Manager.Gate] access;
	// "" ⇒ any authenticated session.
	RequiredGroup string
	// SessionKey seals the session cookie (AES-256-GCM). Required, 32
	// bytes.
	SessionKey []byte
	// SessionTTL is the session lifetime; 0 ⇒ 8h.
	SessionTTL time.Duration

	// CookiePrefix names the session cookie — <prefix>_session. Required,
	// so multiple apps on one host don't collide.
	CookiePrefix string

	// LoginPath, LogoutPath are the routes — as [Manager.Gate] sees
	// r.URL.Path — the login/logout handlers are mounted at. The Gate
	// exempts them and redirects unauthenticated GETs to LoginPath.
	// Defaults: /auth/login, /auth/logout. A caller whose login flow needs
	// its own additional exempt routes (e.g. an OIDC callback) folds them
	// into ExemptPaths.
	LoginPath, LogoutPath string
	// ExemptPaths are extra paths the Gate lets through unauthenticated
	// (e.g. "/healthz", or a login-flow-specific callback route).
	ExemptPaths []string

	// BasePath is the browser-visible prefix the handler tree is mounted
	// under when the caller strips it before routing (e.g.
	// http.StripPrefix("/portal", …) ⇒ BasePath "/portal"). It is the
	// single source for everything that must be expressed in browser
	// space rather than the stripped space the Gate sees:
	//
	//   - every browser-facing redirect — the Gate's login bounce, its
	//     return_to value, the post-login fallback, and the logout
	//     redirect — is prefixed so the Location header names a real URL;
	//   - the session cookie (and any cookie a caller scopes via
	//     [Manager.CookiePath]) is scoped to it (Path=BasePath, or "/"
	//     when unset), so sibling apps on the host never see it.
	//
	// Route matching (LoginPath, ExemptPaths, …) stays in stripped space.
	// Must start with "/"; a trailing slash is normalised away. "" ⇒
	// mounted at root (no prefix, cookie scoped to "/").
	BasePath string

	// IdleTimeout, when > 0, enables sliding-idle-with-absolute-cap
	// renewal: [Manager.Gate] extends a live session's Expiry to
	// now+IdleTimeout on activity (once more than half the window has
	// elapsed since the last extension, to avoid re-sealing the cookie on
	// every single request — the convention common ASP.NET-style sliding-
	// session middleware uses), but never past the session's
	// AbsoluteExpiry (login-time + SessionTTL).
	//
	// 0 (default) ⇒ today's behaviour: Expiry is fixed at login and the
	// session dies at exactly SessionTTL regardless of activity. Prefer
	// that hard-cap-only default for higher-stakes admin surfaces, where
	// bounding exposure regardless of activity matters more than avoiding
	// a mid-task logout; enable IdleTimeout for typical user-facing apps
	// where the UX cost of a hard cap isn't worth it.
	IdleTimeout time.Duration

	// TrustedOrigins both enables and configures the Gate's
	// Origin/Sec-Fetch-Site verification layer (Go's
	// http.CrossOriginProtection), which rejects cross-origin
	// state-changing (non-safe-method) requests before the session/CSRF
	// checks even run:
	//
	//   - nil (the zero value) ⇒ disabled entirely. Default.
	//   - non-nil ⇒ enabled; same-origin requests (and all safe methods)
	//     are always allowed regardless of contents, and each entry
	//     (scheme://host[:port]) in *TrustedOrigins is ALSO allowed. An
	//     empty-but-non-nil pointer (e.g. &[]string{}) is valid and means
	//     "enabled, no additional origins".
	//
	// One field instead of a separate enable flag so "origins configured
	// but the check left off" can't be silently misconfigured.
	//
	// Defense-in-depth alongside the session-bound CSRF tokens in
	// base/csrf — not a replacement: browsers that send neither
	// Sec-Fetch-Site nor Origin (older clients, non-browser callers) are
	// let through by this layer regardless, per
	// http.CrossOriginProtection's documented fail-open behaviour, so the
	// CSRF token remains the layer that must hold on its own.
	TrustedOrigins *[]string

	Now func() time.Time // injectable clock; nil ⇒ time.Now
	Log *slog.Logger     // nil ⇒ slog.Default
}

// Manager owns the sealed session cookie: issuance, the access gate,
// CSRF tokens, and (optionally) Origin verification. Build with [New].
type Manager struct {
	cfg    Config
	cookie sealedcookie.Cookie
	exempt map[string]struct{}
	// originCheck is nil unless Config.TrustedOrigins is set.
	originCheck *http.CrossOriginProtection
}

// New validates cfg and returns a Manager. SessionKey and CookiePrefix are
// required.
func New(cfg Config) (*Manager, error) {
	switch {
	case len(cfg.SessionKey) == 0:
		return nil, errors.New("session: session key is required")
	case cfg.CookiePrefix == "":
		return nil, errors.New("session: cookie prefix is required")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if cfg.LoginPath == "" {
		cfg.LoginPath = defaultLoginPath
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
	cfg.BasePath = strings.TrimSuffix(cfg.BasePath, "/")
	if cfg.BasePath != "" && !strings.HasPrefix(cfg.BasePath, "/") {
		return nil, errors.New("session: BasePath must start with '/'")
	}
	m := &Manager{
		cfg:    cfg,
		exempt: make(map[string]struct{}),
	}
	m.cookie = sealedcookie.Cookie{
		Key:  cfg.SessionKey,
		Name: cfg.CookiePrefix + "_session",
		Path: m.cookiePath(),
		Now:  cfg.Now,
	}
	for _, p := range append([]string{cfg.LoginPath, cfg.LogoutPath}, cfg.ExemptPaths...) {
		m.exempt[p] = struct{}{}
	}
	if cfg.TrustedOrigins != nil {
		cop := http.NewCrossOriginProtection()
		for _, o := range *cfg.TrustedOrigins {
			if err := cop.AddTrustedOrigin(o); err != nil {
				return nil, fmt.Errorf("session: trusted origin %q: %w", o, err)
			}
		}
		cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cfg.Log.Warn("session: cross-origin request denied",
				"method", r.Method, "path", r.URL.Path,
				"origin", r.Header.Get("Origin"),
				"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		}))
		m.originCheck = cop
	}
	return m, nil
}

// NewSession returns a fresh [Session] with Expiry (now + SessionTTL) and a
// new CSRFSecret set — the starting point for a login. The caller
// populates Subject/Email/Name/Groups/Extra from whatever identity source
// authenticated the request, then calls [Manager.IssueSession].
func (m *Manager) NewSession() (Session, error) {
	secret, err := csrf.NewSecret()
	if err != nil {
		return Session{}, fmt.Errorf("session: csrf secret: %w", err)
	}
	now := m.cfg.Now()
	absExpiry := now.Add(m.cfg.SessionTTL)
	expiry := absExpiry
	// Start within the idle window (not at the full absolute ceiling) when
	// idle extension is enabled and actually narrower than the absolute
	// cap — otherwise the first several hours of an 8h session would sit
	// comfortably above the "more than half the idle window elapsed"
	// threshold in [Manager.Gate] and idle expiry would never engage.
	if m.cfg.IdleTimeout > 0 && m.cfg.IdleTimeout < m.cfg.SessionTTL {
		expiry = now.Add(m.cfg.IdleTimeout)
	}
	return Session{
		Expiry:         expiry,
		AbsoluteExpiry: absExpiry,
		CSRFSecret:     secret,
	}, nil
}

// IssueSession seals sess into the session cookie, establishing it as the
// request's live session. Call once the caller's login flow has verified
// the identity and populated the [Session] (typically one returned by
// [Manager.NewSession]).
func (m *Manager) IssueSession(w http.ResponseWriter, r *http.Request, sess Session) error {
	return m.cookie.Set(w, r, sess, sess.Expiry.Sub(m.cfg.Now()))
}

// UpdateSession applies mutate to the request's live session and re-seals
// it into the cookie. Use it for consumer state that changes during the
// session's lifetime, e.g. an active-tenant choice stored in
// [Session.Extra].
//
// Expiry is preserved unless mutate changes it: an update is not a
// renewal. Returns an error — writing nothing — when the request carries
// no valid session or the mutation/seal fails.
//
// Note the session injected into the CURRENT request's context by
// [Manager.Gate] still holds the pre-update copy; the mutating handler
// already has the new value in hand, and later requests read the updated
// cookie.
func (m *Manager) UpdateSession(w http.ResponseWriter, r *http.Request, mutate func(*Session) error) error {
	sess, ok := m.readSession(r)
	if !ok {
		return errors.New("session: no valid session")
	}
	if err := mutate(&sess); err != nil {
		return err
	}
	return m.cookie.Set(w, r, sess, sess.Expiry.Sub(m.cfg.Now()))
}

// CSRFToken returns the session-bound anti-CSRF token for scope — embed it
// in each form the consumer renders (hidden field) and check it on POST
// with [Manager.ValidateCSRF]. These are thin session-plumbing wrappers
// over [csrf.Token]/[csrf.Validate] (see base/csrf for the token scheme:
// HMAC over [Session.CSRFSecret], per-render masking, constant-time
// verification). Errors when the request carries no valid session.
func (m *Manager) CSRFToken(r *http.Request, scope string) (string, error) {
	sess, ok := m.readSession(r)
	if !ok || sess.CSRFSecret == "" {
		return "", errors.New("session: no valid session to bind a CSRF token to")
	}
	return csrf.Token(sess.CSRFSecret, scope)
}

// ValidateCSRF reports whether token is a valid CSRF token for the
// request's session and scope. False on a missing/expired session or any
// token defect — uniformly, so handlers render one "expired or forged"
// message.
func (m *Manager) ValidateCSRF(r *http.Request, token, scope string) bool {
	sess, ok := m.readSession(r)
	if !ok {
		return false
	}
	return csrf.Validate(sess.CSRFSecret, token, scope)
}

// LogoutHandler clears the session cookie and redirects to the login route.
func (m *Manager) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.cookie.Clear(w, r)
		http.Redirect(w, r, m.cfg.BasePath+m.cfg.LoginPath, http.StatusSeeOther)
	}
}

// Gate wraps next behind a valid session and, when RequiredGroup is set,
// membership in it. The configured login/logout routes and any
// ExemptPaths are let through. A GET without a session redirects to
// LoginPath (carrying return_to); a non-GET answers 401 (its body can't
// survive a redirect round-trip). On success the [Session] is injected
// into the request context for [SessionFromContext].
func (m *Manager) Gate(next http.Handler) http.Handler {
	gated := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := m.exempt[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		sess, ok := m.readSession(r)
		if !ok {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, m.cfg.BasePath+m.cfg.LoginPath+"?return_to="+url.QueryEscape(m.cfg.BasePath+r.URL.Path), http.StatusSeeOther)
				return
			}
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if g := m.cfg.RequiredGroup; g != "" && !slices.Contains(sess.Groups, g) {
			http.Error(w, "forbidden: requires membership in "+g, http.StatusForbidden)
			return
		}
		sess = m.maybeExtendIdle(w, r, sess)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sess)))
	})
	// Outermost when enabled: a cross-origin state-changing request is
	// rejected before it even reaches the session cookie / CSRF checks.
	if m.originCheck != nil {
		return m.originCheck.Handler(gated)
	}
	return gated
}

// SiblingCookie returns a [sealedcookie.Cookie] sharing this Manager's
// SessionKey, cookie-scope Path, and clock, but named
// "<CookiePrefix>_<suffix>" instead of "<CookiePrefix>_session" — for a
// caller's own related cookie (e.g. an OIDC login-flow state) that should
// be scoped, keyed, and clocked identically to the session cookie without
// duplicating SessionKey/CookiePrefix/Now into the caller's own config.
func (m *Manager) SiblingCookie(suffix string) sealedcookie.Cookie {
	return sealedcookie.Cookie{
		Key:  m.cfg.SessionKey,
		Name: m.cfg.CookiePrefix + "_" + suffix,
		Path: m.cookiePath(),
		Now:  m.cfg.Now,
	}
}

// Log returns the configured logger (never nil after [New]). Exposed so a
// caller composing its own login-flow handler (e.g. base/oidc) can log
// through the same sink without also requiring its own Log field.
func (m *Manager) Log() *slog.Logger { return m.cfg.Log }

// IsExempt reports whether path is in the Gate's exempt set (LoginPath,
// LogoutPath, and Config.ExemptPaths, matched exactly as [Manager.Gate]
// sees r.URL.Path). Exposed for a caller composing its own login-flow
// handler at a route outside this set (e.g. an OIDC callback) to verify at
// construction time that its route is actually exempt — an unexempted
// callback route would otherwise be silently redirected to LoginPath
// before it could ever run.
func (m *Manager) IsExempt(path string) bool {
	_, ok := m.exempt[path]
	return ok
}

// CookiePath is the normalised cookie scope derived from BasePath ("/" for
// a root mount). Exposed so a caller layering its own cookies (e.g.
// base/oidc's login-flow cookie) can scope them identically without
// re-deriving BasePath normalisation itself.
func (m *Manager) CookiePath() string {
	return m.cookiePath()
}

// SafeReturnTo confines an untrusted "return to this path after login"
// value to a local absolute path under BasePath, so a crafted value can't
// bounce the browser to an attacker origin. An absent or unsafe value
// falls back to the browser-space mount root (BasePath + "/"), not the
// bare "/" — under a stripped mount the latter names a URL outside the
// handler tree. Exposed for a caller's login-flow handler (e.g. base/oidc's
// LoginHandler) to sanitise a return_to query parameter before sealing it
// into its own flow state.
func (m *Manager) SafeReturnTo(p string) string {
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") {
		return p
	}
	return m.cfg.BasePath + "/"
}

// maybeExtendIdle re-issues the session cookie with Expiry pushed out to
// now+IdleTimeout (capped at AbsoluteExpiry) when idle-based extension is
// enabled ([Config.IdleTimeout] > 0) and more than half the idle window has
// elapsed since the last extension. A no-op (returning sess unchanged) when
// idle extension is disabled, when the session is already within the first
// half of its current idle window, or once the absolute cap has been
// reached (nothing left to extend). A failed re-seal is logged and the
// original session returned so the request still proceeds on its
// still-valid cookie.
func (m *Manager) maybeExtendIdle(w http.ResponseWriter, r *http.Request, sess Session) Session {
	if m.cfg.IdleTimeout <= 0 {
		return sess
	}
	now := m.cfg.Now()
	if sess.Expiry.Sub(now) > m.cfg.IdleTimeout/2 {
		return sess // recently extended (or freshly issued) — nothing to do yet
	}
	extended := sess
	extended.Expiry = now.Add(m.cfg.IdleTimeout)
	if abs := sess.AbsoluteExpiry; !abs.IsZero() && extended.Expiry.After(abs) {
		extended.Expiry = abs
	}
	if !extended.Expiry.After(sess.Expiry) {
		return sess // already at (or past) the absolute cap; nothing to extend
	}
	if err := m.cookie.Set(w, r, extended, extended.Expiry.Sub(now)); err != nil {
		m.cfg.Log.Warn("session: idle-extend re-seal failed; continuing with existing cookie", "err", err)
		return sess
	}
	return extended
}

// readSession returns the live (unexpired) session from the request cookie.
func (m *Manager) readSession(r *http.Request) (Session, bool) {
	var sess Session
	if err := m.cookie.Read(r, &sess); err != nil {
		return Session{}, false
	}
	if m.cfg.Now().After(sess.Expiry) {
		return Session{}, false
	}
	return sess, true
}

type ctxKey int

const sessionCtxKey ctxKey = 0

// SessionFromContext returns the session [Manager.Gate] injected, if any.
func SessionFromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionCtxKey).(Session)
	return s, ok
}

// cookiePath scopes the session cookie to the mount. RFC 6265
// path-matching makes cookie-path "/portal" cover both "/portal" and
// "/portal/…" (but not "/portalx"), so the un-slashed BasePath is exactly
// right; an empty BasePath (root mount) scopes to "/".
func (m *Manager) cookiePath() string {
	if m.cfg.BasePath == "" {
		return "/"
	}
	return m.cfg.BasePath
}
