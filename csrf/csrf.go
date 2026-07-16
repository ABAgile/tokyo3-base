// Package csrf implements anti-CSRF token minting and validation for the
// tokyo3 web surfaces. It is deliberately pure token math: no cookie, no
// HTTP. It knows nothing about where the secret it signs over is stored —
// that is entirely the caller's job.
//
// One pattern (OWASP synchronizer/signed family): the caller stores a
// [NewSecret] wherever its authenticated session state lives (e.g.
// base/session seals it into the session cookie), renders [Token] into
// each form, and checks [Validate] on POST. Tokens are HMAC-SHA256 over
// the secret, so forging one requires forging the state holding the
// secret itself — immune to the cookie-planting weakness of naive
// double-submit schemes.
//
// Every token [Token] returns is XOR-masked with a fresh random
// pad per call (the Django/Rails scheme) before being returned for
// rendering: every render emits different wire bytes while the underlying
// derived HMAC stays stable for the secret's whole lifetime — multi-tab
// keeps working, nothing rotates server-side. This defeats compression
// side-channels (BREACH) against the embedded value: classically
// demonstrated against exactly this shape of token — a per-session secret
// reflected verbatim into HTML pages that also echo attacker-influenceable
// content (e.g. a form re-populated with the submitted values after a
// validation error). All comparisons are constant-time.
package csrf

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/abagile/tokyo3-base/crypto"
)

// Secret binds anti-CSRF tokens: mint them with [Token], check them with
// [Validate]. Generate one with [NewSecret] and store it with the session
// state it protects (it marshals as a plain string); rotating it
// invalidates every token issued under it. The zero value "" mints
// nothing and validates nothing.
type Secret string

// NewSecret returns a fresh 32-byte random [Secret], base64url-encoded.
func NewSecret() (Secret, error) {
	b, err := crypto.RandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("csrf: secret: %w", err)
	}
	return Secret(base64.RawURLEncoding.EncodeToString(b)), nil
}

// Token returns a masked token for secret+scope to embed in a form
// (hidden field), or an error if none can be minted (empty secret, no
// entropy). scope partitions the token space (e.g. per form action); ""
// yields one token space per secret. Every call returns different wire
// bytes for the same secret+scope (see package doc re: BREACH masking).
// Stateless: nothing is stored per form.
func Token(secret Secret, scope string) (string, error) {
	if secret == "" {
		return "", errors.New("csrf: empty secret")
	}
	return mask(derive(secret, scope))
}

// Validate reports whether token is a valid token for secret+scope. False
// on an empty secret, an empty/malformed token, or a mismatch —
// uniformly, so handlers render one "expired or forged" message.
func Validate(secret Secret, token, scope string) bool {
	if secret == "" || token == "" {
		return false
	}
	real, err := unmask(token, sha256.Size)
	if err != nil {
		return false
	}
	return hmac.Equal(derive(secret, scope), real)
}

// derive is the shared derivation: HMAC-SHA256(secret, scope), raw. Never
// sent on the wire directly — [Token] masks it per call.
func derive(secret Secret, scope string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(scope))
	return m.Sum(nil)
}

// mask returns base64url(pad ‖ real⊕pad) with a fresh random pad each call
// — so [Token] never puts a static value in a response body (see package
// comment re: BREACH).
func mask(real []byte) (string, error) {
	pad, err := crypto.RandomBytes(len(real))
	if err != nil {
		return "", fmt.Errorf("csrf: pad: %w", err)
	}
	wire := make([]byte, 2*len(real))
	copy(wire, pad)
	subtle.XORBytes(wire[len(real):], real, pad)
	return base64.RawURLEncoding.EncodeToString(wire), nil
}

// unmask reverses [mask], recovering the wantLen-byte real value from a
// wire token, or an error if token is malformed / the wrong length.
func unmask(token string, wantLen int) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 2*wantLen {
		return nil, errors.New("csrf: malformed token")
	}
	real := make([]byte, wantLen)
	subtle.XORBytes(real, raw[:wantLen], raw[wantLen:])
	return real, nil
}
