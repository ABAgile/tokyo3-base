package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// LogoutTokenVerifier validates an OIDC Back-Channel Logout 1.0
// logout_token. *HTTPVerifier and *LazyVerifier both satisfy this
// verbatim via their VerifyLogoutToken method.
type LogoutTokenVerifier interface {
	VerifyLogoutToken(ctx context.Context, raw string) (*LogoutClaims, error)
}

// LogoutRevoker is what a BackchannelLogoutHandler revokes against —
// implementations map a verified OIDC Back-Channel Logout 1.0
// notification onto their own session/token model.
type LogoutRevoker interface {
	// RevokeSession revokes every session/token chained to the OP
	// session id (the logout_token's sid claim), returning how many
	// were revoked. Called when the logout_token carries sid — the
	// precise path, per OIDC Back-Channel Logout 1.0.
	RevokeSession(ctx context.Context, sid string) (revoked int64, err error)

	// RevokeUser revokes every session/token for the user identified
	// by (issuer, subject) — the fallback used when the logout_token
	// carries only sub. identity is an opaque, revoker-defined
	// description of who was revoked (e.g. an email address), passed
	// through to BackchannelLogoutConfig.OnRevoked for audit use;
	// empty when ok is false. ok=false means the revoker has no
	// record of this issuer+subject pair — treated as an idempotent
	// success (a logout notification for a user the RP doesn't know
	// about needs no action, and the OP shouldn't keep retrying it),
	// not an error.
	RevokeUser(ctx context.Context, issuer, subject string) (revoked int64, identity string, ok bool, err error)
}

// BackchannelLogoutConfig wires a BackchannelLogoutHandler.
type BackchannelLogoutConfig struct {
	// Verifier validates the logout_token. Required.
	Verifier LogoutTokenVerifier
	// Revoker maps a verified notification onto the caller's own
	// session/token model. Required.
	Revoker LogoutRevoker
	// ReplayWindow bounds how long a jti is remembered for replay
	// rejection. <= 0 defaults to 5 minutes — comfortably covers a
	// logout_token's typical short exp plus worst-case clock skew,
	// while bounding memory (single-process only; see the internal
	// jti cache this handler keeps).
	ReplayWindow time.Duration
	// OnRevoked, if set, runs after a successful revocation
	// (including the "unknown user" idempotent case) so the caller
	// can audit-log with its own metadata shape. scope is "session"
	// or "user"; identity is RevokeUser's returned identity ("" for
	// the session-scoped path); revoked is the deletion count (0 for
	// "unknown user"). A returned error fails the whole request with
	// 500 — for a caller that wants the OP to retry when it can't
	// durably record the logout, even though the revocation itself
	// already happened.
	OnRevoked func(r *http.Request, claims *LogoutClaims, scope, identity string, revoked int64) error
	// Log receives warnings for verify/replay failures and errors for
	// revocation/OnRevoked failures. nil ⇒ slog.Default().
	Log *slog.Logger
}

// BackchannelLogoutHandler consumes OIDC Back-Channel Logout 1.0
// notifications and revokes the corresponding sessions/tokens via the
// injected LogoutRevoker. Build with NewBackchannelLogoutHandler and
// mount its ServeHTTP at the route the OP is configured to POST
// logout_tokens to.
type BackchannelLogoutHandler struct {
	cfg BackchannelLogoutConfig
	jti *logoutJTICache
}

// NewBackchannelLogoutHandler validates cfg and returns a handler.
// Verifier and Revoker are required.
func NewBackchannelLogoutHandler(cfg BackchannelLogoutConfig) (*BackchannelLogoutHandler, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("oidc: backchannel logout verifier is required")
	}
	if cfg.Revoker == nil {
		return nil, errors.New("oidc: backchannel logout revoker is required")
	}
	if cfg.ReplayWindow <= 0 {
		cfg.ReplayWindow = 5 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &BackchannelLogoutHandler{cfg: cfg, jti: newLogoutJTICache(cfg.ReplayWindow)}, nil
}

// ServeHTTP implements OIDC Back-Channel Logout 1.0 (§2.5-2.8): parses
// the form-encoded logout_token, verifies it, rejects a replayed jti,
// dispatches to RevokeSession (sid present) or RevokeUser (sub-only
// fallback), and runs OnRevoked if configured.
//
// Per §2.5 the request is application/x-www-form-urlencoded with a
// single logout_token field; the body carries no client credentials —
// the JWT signature is the authentication. Per §2.8 the response is
// Cache-Control: no-store and 200 on success; errors are 4xx (missing
// or invalid logout_token, replay) or 5xx (an unexpected internal
// failure). The OP does not retry on failure, so OnRevoked (or the
// caller's own logging) is the only post-mortem signal.
func (h *BackchannelLogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	raw := r.PostFormValue("logout_token")
	if raw == "" {
		http.Error(w, "logout_token required", http.StatusBadRequest)
		return
	}

	claims, err := h.cfg.Verifier.VerifyLogoutToken(r.Context(), raw)
	if err != nil {
		h.cfg.Log.Warn("oidc: backchannel logout verify failed", "err", err)
		http.Error(w, "invalid logout_token", http.StatusBadRequest)
		return
	}
	if !h.jti.accept(claims.JTI, time.Now()) {
		h.cfg.Log.Warn("oidc: backchannel logout replay", "jti", claims.JTI)
		http.Error(w, "logout_token replay", http.StatusBadRequest)
		return
	}

	var (
		scope, identity string
		revoked         int64
	)
	if claims.SessionID != "" {
		n, err := h.cfg.Revoker.RevokeSession(r.Context(), claims.SessionID)
		if err != nil {
			h.cfg.Log.Error("oidc: backchannel logout revoke by session", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		revoked, scope = n, "session"
	} else {
		n, id, ok, err := h.cfg.Revoker.RevokeUser(r.Context(), claims.Issuer, claims.Subject)
		if err != nil {
			h.cfg.Log.Error("oidc: backchannel logout revoke by user", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if ok {
			revoked, identity = n, id
		} else {
			h.cfg.Log.Info("oidc: backchannel logout unknown user", "sub", claims.Subject)
		}
		scope = "user"
	}

	if h.cfg.OnRevoked != nil {
		if err := h.cfg.OnRevoked(r, claims, scope, identity, revoked); err != nil {
			h.cfg.Log.Error("oidc: backchannel logout OnRevoked failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// logoutJTICache provides single-process replay protection for
// incoming logout_tokens: a jti seen within window is rejected
// regardless of whether its signature still verifies — the JWT spec
// leaves replay defense to relying parties, and OIDC Back-Channel
// Logout §2.6 explicitly recommends it.
//
// Single-process only: a multi-replica deployment would want a
// DB-backed table or a shared cache instead of this in-memory map.
type logoutJTICache struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	window time.Duration
}

func newLogoutJTICache(window time.Duration) *logoutJTICache {
	return &logoutJTICache{seen: map[string]time.Time{}, window: window}
}

// accept records jti and reports whether this is the first time it's
// been seen within window — false means replay. Sweeps expired
// entries on every call; cheap since the map stays small (one entry
// per logout in the last window).
func (c *logoutJTICache) accept(jti string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-c.window)
	for k, t := range c.seen {
		if t.Before(cutoff) {
			delete(c.seen, k)
		}
	}
	if _, dup := c.seen[jti]; dup {
		return false
	}
	c.seen[jti] = now
	return true
}
