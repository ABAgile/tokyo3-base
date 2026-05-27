package jwt

import (
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// backchannelLogoutEventURI is the literal identifier the RP looks
// for in the `events` claim per OIDC Back-Channel Logout 1.0 §2.4.
// The value is fixed by the spec — no other event types are emitted
// on this URL.
const backchannelLogoutEventURI = "http://schemas.openid.net/event/backchannel-logout"

// logoutTokenTTL is the lifetime stamped into every logout_token. The
// spec recommends short-lived tokens; 2 minutes is enough for the
// receiving RP to validate + persist the revocation before expiry.
// Not lifted to Config because operators have no reason to tune it.
const logoutTokenTTL = 2 * time.Minute

// LogoutClaims is the JWT body of an OIDC Back-Channel Logout 1.0
// logout_token.
//
// Per §2.4 a logout_token MUST contain iss, aud, iat, jti, and
// `events` with the back-channel logout member set to an empty
// object; it MUST NOT contain a `nonce` claim. It SHOULD contain
// `sub` and/or `sid` — RPs use `sid` (when present) for session-
// scoped revocation and fall back to `sub` for whole-user revocation.
// Verifiers must reject any logout_token where `nonce` appears
// (replay-against-ID-token defence per §2.6).
type LogoutClaims struct {
	gojwt.RegisteredClaims
	SID    string                    `json:"sid,omitempty"`
	Events map[string]map[string]any `json:"events"`
}

// MintLogoutToken issues a signed RS256 JWT suitable for POSTing to
// an RP's backchannel_logout_uri. sid scopes the logout to a specific
// OP session row (empty = whole-user logout).
//
// jti is supplied by the caller so the OP can log the same value RPs
// use for replay detection — easier post-mortems when something goes
// wrong. Empty jti causes the package to generate one (uuid.NewString).
func (s *Signer) MintLogoutToken(audience, sub, sid, jti string, now time.Time) (string, error) {
	if jti == "" {
		jti = uuid.NewString()
	}
	claims := LogoutClaims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   sub,
			Audience:  gojwt.ClaimStrings{audience},
			IssuedAt:  gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(now.Add(logoutTokenTTL)),
			ID:        jti,
		},
		SID: sid,
		Events: map[string]map[string]any{
			backchannelLogoutEventURI: {},
		},
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.privateKey)
}
