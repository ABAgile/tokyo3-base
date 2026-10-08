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
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/abagile/tokyo3-base/clientip"
	"github.com/abagile/tokyo3-base/crypto"
)

// maxValueLen caps the sealed value so name, attributes, and value stay under
// the ~4096-byte per-cookie limit; browsers silently drop larger cookies.
const maxValueLen = 3800

// Cookie manages one sealed cookie: a fixed key, name, path, and clock.
// The zero value is not usable — construct with the fields set; Now nil
// falls back to time.Now.
type Cookie struct {
	Key  []byte           // AES-256-GCM key
	Name string           // cookie name
	Path string           // cookie Path scope
	Now  func() time.Time // nil ⇒ time.Now

	// Proxies, when it has trusted proxies configured, restricts which peers
	// may vouch for TLS via X-Forwarded-Proto when deciding the Secure flag —
	// the same trust model clientip applies to X-Forwarded-For. nil, or an
	// Extractor with no trusted proxies, keeps the legacy behaviour: the
	// header is believed from any peer. Direct TLS (r.TLS) always marks the
	// cookie Secure.
	Proxies *clientip.Extractor
}

// keySize is the AES-256 key length Cookie requires.
const keySize = 32

// Validate reports whether c is usable: a 32-byte key and a name net/http
// will actually send. net/http silently drops a cookie with an invalid name
// in Set, so catching it here turns a mysterious runtime failure into a
// construction error.
func (c Cookie) Validate() error {
	if len(c.Key) != keySize {
		return fmt.Errorf("sealedcookie: key must be %d bytes, got %d", keySize, len(c.Key))
	}
	if c.Name == "" {
		return errors.New("sealedcookie: name is required")
	}
	if err := (&http.Cookie{Name: c.Name, Value: "x", Path: c.Path}).Valid(); err != nil {
		return fmt.Errorf("sealedcookie: %w", err)
	}
	return nil
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
	sealed, err := c.Seal(v)
	if err != nil {
		return err
	}
	if len(sealed) > maxValueLen {
		return fmt.Errorf("sealedcookie: %q value is %d bytes, over the %d-byte limit browsers accept", c.Name, len(sealed), maxValueLen)
	}
	ck := &http.Cookie{
		Name:     c.Name,
		Value:    sealed,
		Path:     c.Path,
		HttpOnly: true,
		Secure:   c.isHTTPS(r),
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
		Secure:   c.isHTTPS(r),
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
	return c.Open(ck.Value, dst)
}

// Seal marshals v to JSON and encrypts it (AES-256-GCM) with the cookie's
// key, bound to the cookie's name, returning a base64url string suitable for
// its value. A value sealed for one cookie name never opens under another,
// even when cookies share a key (see session.Manager.SiblingCookie).
func (c Cookie) Seal(v any) (string, error) {
	return seal(c.Key, v, c.aad())
}

// Open reverses [Cookie.Seal]: decodes, decrypts, and unmarshals into dst.
func (c Cookie) Open(val string, dst any) error {
	return open(c.Key, val, dst, c.aad())
}

func (c Cookie) aad() []byte { return []byte("sealedcookie:" + c.Name) }

// Seal marshals v to JSON and encrypts it with key (AES-256-GCM),
// returning a base64url string. Unlike [Cookie.Seal] it is not bound to a
// cookie name; prefer the Cookie methods for anything set as a cookie.
func Seal(key []byte, v any) (string, error) { return seal(key, v, nil) }

// Open reverses [Seal]: decodes, decrypts with key, and unmarshals into dst.
func Open(key []byte, val string, dst any) error { return open(key, val, dst, nil) }

func seal(key []byte, v any, aad []byte) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sealed, err := crypto.SealAAD(key, b, aad)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func open(key []byte, val string, dst any, aad []byte) error {
	raw, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil {
		return err
	}
	pt, err := crypto.OpenAAD(key, raw, aad)
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
//
// When [Cookie.Proxies] lists trusted proxies, X-Forwarded-Proto is honoured
// only from those peers, so a client can't assert it itself. Without a list
// it is honoured from any peer (legacy behaviour).
func (c Cookie) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if r.Header.Get("X-Forwarded-Proto") != "https" {
		return false
	}
	return !c.Proxies.HasTrustedProxies() || c.Proxies.IsTrustedPeer(r)
}
