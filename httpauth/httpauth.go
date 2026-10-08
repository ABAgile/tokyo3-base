// Package httpauth holds small, reusable HTTP authentication middlewares
// shared by the daemons' admin portals. Today that is an HTTP Basic gate;
// session/OIDC helpers may join it as a second consumer appears.
package httpauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
)

// BasicAuthConfig wires the optional HTTP Basic auth gate. When BOTH
// credentials are empty the gate is disabled and the wrapped handler is served
// unguarded — operators front the service with oauth2-proxy, an mTLS reverse
// proxy, or another identity-aware edge instead. Setting exactly one is a
// misconfiguration (e.g. a missing password env var): [BasicAuthConfig.Validate]
// reports it and [BasicAuth] fails closed rather than serve unguarded.
type BasicAuthConfig struct {
	// Username is the only accepted login.
	Username string

	// Password is the corresponding secret.
	Password string

	// Realm is sent in the WWW-Authenticate header on rejection. Empty ⇒
	// "restricted".
	Realm string
}

// Enabled reports whether the gate is configured: both credentials set. A
// half-configured gate is not enabled but is invalid — see
// [BasicAuthConfig.Validate].
func (c BasicAuthConfig) Enabled() bool {
	return c.Username != "" && c.Password != ""
}

// Validate returns an error when exactly one of Username and Password is set.
// Call it at startup to fail fast on a half-configured gate instead of
// silently serving the portal unauthenticated.
func (c BasicAuthConfig) Validate() error {
	if (c.Username == "") != (c.Password == "") {
		return errors.New("httpauth: basic auth username and password must be set together")
	}
	return nil
}

// BasicAuth wraps next with an HTTP Basic gate. When the config is disabled
// it returns next unchanged. A half-configured gate (see
// [BasicAuthConfig.Validate]) fails closed: every non-exempt request is
// answered 503. When enabled, every request must present the
// configured Username + Password — constant-time compared on a sha256 digest
// of each side, so equal-length inputs reach subtle.ConstantTimeCompare
// regardless of attacker guess length.
//
// Paths in exempt (exact match) bypass the gate — pass "/healthz" so external
// watchdogs can probe without sharing the admin credentials.
func BasicAuth(cfg BasicAuthConfig, next http.Handler, exempt ...string) http.Handler {
	if cfg.Validate() != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if slices.Contains(exempt, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "authentication misconfigured", http.StatusServiceUnavailable)
		})
	}
	if !cfg.Enabled() {
		return next
	}
	realm := cfg.Realm
	if realm == "" {
		realm = "restricted"
	}
	// Pre-hash the expected credentials once so each request avoids
	// re-hashing the configured secret.
	wantUser := sha256.Sum256([]byte(cfg.Username))
	wantPass := sha256.Sum256([]byte(cfg.Password))

	exemptSet := make(map[string]struct{}, len(exempt))
	for _, p := range exempt {
		exemptSet[p] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := exemptSet[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			challenge(w, realm)
			return
		}
		gotUser := sha256.Sum256([]byte(user))
		gotPass := sha256.Sum256([]byte(pass))
		userOK := subtle.ConstantTimeCompare(gotUser[:], wantUser[:])
		passOK := subtle.ConstantTimeCompare(gotPass[:], wantPass[:])
		if userOK&passOK != 1 {
			challenge(w, realm)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// challenge returns 401 with the WWW-Authenticate header so browsers pop their
// credential prompt and curl/CI know to retry with -u.
func challenge(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}
