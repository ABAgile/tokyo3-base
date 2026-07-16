// Package sealedcookie implements one sealed (AES-256-GCM), single-purpose
// HTTP cookie: marshal a value to JSON, seal it with a key, and set/clear/
// read it under a fixed name, path, and clock. It has no notion of what
// the value MEANS — a long-lived login session and a short-lived OIDC
// login-flow state (state/nonce/PKCE verifier) are both just "a value,
// sealed into a cookie, for some TTL" as far as this package is concerned;
// base/session and base/oidc each compose one for their own payload type.
package sealedcookie

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/abagile/tokyo3-base/crypto"
)

// Cookie manages one sealed cookie: a fixed key, name, path, and clock.
// The zero value is not usable — construct with the fields set; Now nil
// falls back to time.Now.
type Cookie struct {
	Key  []byte           // AES-256-GCM key
	Name string           // cookie name
	Path string           // cookie Path scope
	Now  func() time.Time // nil ⇒ time.Now
}

func (c Cookie) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Set marshals v to JSON, seals it, and sets the cookie with the given TTL.
// ttl <= 0 sets no Expires/Max-Age — a browser-session cookie, cleared when
// the browser closes.
func (c Cookie) Set(w http.ResponseWriter, r *http.Request, v any, ttl time.Duration) error {
	sealed, err := Seal(c.Key, v)
	if err != nil {
		return err
	}
	ck := &http.Cookie{
		Name:     c.Name,
		Value:    sealed,
		Path:     c.Path,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	}
	if ttl > 0 {
		ck.Expires = c.now().Add(ttl)
		ck.MaxAge = int(ttl.Seconds())
	}
	http.SetCookie(w, ck)
	return nil
}

// Clear removes the cookie.
func (c Cookie) Clear(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.Name,
		Value:    "",
		Path:     c.Path,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// Read looks up the cookie on r and unseals it into dst. Returns a single
// uniform error whether the cookie is absent, malformed, or fails to open
// — callers that already treat "no valid value" as one case (expired
// login flow, no session, …) don't need to distinguish the two.
func (c Cookie) Read(r *http.Request, dst any) error {
	ck, err := r.Cookie(c.Name)
	if err != nil {
		return err
	}
	return Open(c.Key, ck.Value, dst)
}

// Seal marshals v to JSON and encrypts it with key (AES-256-GCM),
// returning a base64url string suitable for a cookie value.
func Seal(key []byte, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sealed, err := crypto.Seal(key, b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open reverses [Seal]: decodes, decrypts with key, and unmarshals into dst.
func Open(key []byte, val string, dst any) error {
	raw, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil {
		return err
	}
	pt, err := crypto.Open(key, raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(pt, dst)
}

// isHTTPS reports whether the request arrived over TLS, directly or via a
// proxy that recorded it in X-Forwarded-Proto. Drives the Secure flag on
// [Cookie.Set]/[Cookie.Clear]: true on TLS, false over plaintext so dev /
// curl-test setups keep working.
//
// r.TLS alone only reflects the DIRECT connection to this process —
// behind a TLS-terminating reverse proxy forwarding plaintext internally
// (a common deployment shape: traefik/nginx/an ALB terminates TLS at the
// edge), r.TLS is nil even though the browser-facing connection is
// genuinely HTTPS, which would incorrectly mark the cookie non-Secure.
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}
