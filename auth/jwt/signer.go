// Package jwt is the RS256 signer + JWT claim shapes used by the auth
// IdP server and by any other OIDC-shaped tool that needs to mint
// identity, federation, or back-channel-logout tokens. Sits under the
// auth/ namespace alongside auth/oidcclient, auth/creds, and
// auth/awsclaims.
//
// The package is a stateless primitive: callers supply the loaded RSA
// private key + KID + issuer at construction and the lifted policy
// parameters via Config. Key management (load-or-generate from a
// keystore, JWKS publishing from a keystore) lives in callers — they
// already know which storage layer they're using; this package
// shouldn't dictate one.
//
// Deployment policy is lifted via Config: ID-token TTL, federation
// token default TTL, and the ACR string emitted when an MFA-verified
// session signs an ID token. Pass zero values to accept the package
// defaults (1h ID, 15m federation, urn:mace:incommon:iap:silver).
package jwt

import (
	"crypto/rsa"
	"sort"
	"time"

	"github.com/abagile/tokyo3-base/auth/awsclaims"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Defaults applied when the corresponding Config field is zero/empty.
// Values match the original auth-IdP defaults — operators who want
// different numbers populate Config explicitly.
const (
	DefaultIDTokenTTL         = 1 * time.Hour
	DefaultFederationTokenTTL = 15 * time.Minute
	DefaultACRMFA             = "urn:mace:incommon:iap:silver"
)

// Config holds the lifted policy parameters. Zero/empty fields fall
// back to the Default* constants above.
type Config struct {
	// IDTokenTTL bounds an OIDC ID token's lifetime; signed into the
	// exp claim at every MintIDToken call.
	IDTokenTTL time.Duration

	// FederationTokenTTL is the fallback used by MintFederationToken
	// when the caller passes zero. Callers can still override on a
	// per-call basis (some federation flows want a tighter window).
	FederationTokenTTL time.Duration

	// ACRMFA is emitted as the acr claim when MintIDToken is called
	// with mfaVerified=true. The default
	// (urn:mace:incommon:iap:silver) is the InCommon IAP "silver"
	// assurance level, which most OIDC RPs map to "user proved
	// they're a human plus a second factor."
	ACRMFA string
}

// IDClaims holds standard OIDC ID token claims.
//
// SID is the OIDC Back-Channel Logout 1.0 `sid` claim — a stable
// identifier for the user's session at the OP that's emitted on every
// ID token minted under that session (initial code grant + every
// refresh). RPs persist `sid` on their own session row at first
// issuance so a later logout_token POST can tell them which local
// session to invalidate. Omitted when the caller passes the empty
// string (e.g. session-less client-credentials flows).
type IDClaims struct {
	gojwt.RegisteredClaims
	Nonce             string   `json:"nonce,omitempty"`
	AuthTime          int64    `json:"auth_time"`
	ACR               string   `json:"acr,omitempty"`
	AMR               []string `json:"amr,omitempty"`
	SID               string   `json:"sid,omitempty"`
	Email             string   `json:"email,omitempty"`
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	// Groups carries the user's group memberships. Gated by the
	// caller on the `groups` OAuth scope so clients that don't
	// request it don't get bloated tokens. Consumed by RPs that map
	// roles from a group/team claim (OpenSearch Security
	// `backend_roles`, Vault JWT auth `claim_mappings`, etc.).
	Groups []string `json:"groups,omitempty"`
}

// FederationClaims is the JWT payload shape minted by
// MintFederationToken and exchanged for STS credentials via
// sts:AssumeRoleWithWebIdentity. The ordinary OIDC claims are
// informational; the mechanism that actually delivers user attributes
// into AWS's policy-evaluation context is the AWSTags claim, which
// STS expands into `aws:PrincipalTag/<key>`. Claim name + shape come
// from auth/awsclaims for single-source-of-truth.
type FederationClaims struct {
	gojwt.RegisteredClaims
	Email             string                        `json:"email,omitempty"`
	Name              string                        `json:"name,omitempty"`
	PreferredUsername string                        `json:"preferred_username,omitempty"`
	Groups            []string                      `json:"groups,omitempty"`
	AMR               []string                      `json:"amr,omitempty"`
	AuthTime          int64                         `json:"auth_time,omitempty"`
	AWSTags           *awsclaims.PrincipalTagsValue `json:"https://aws.amazon.com/tags,omitempty"`
}

// Signer holds an active RS256 private key plus the issuer + config
// applied to every minted token.
type Signer struct {
	privateKey *rsa.PrivateKey
	kid        string
	issuer     string
	cfg        Config
}

// New returns a Signer that mints under the supplied private key.
// Zero/empty Config fields fall back to the package defaults. Callers
// that already have the key (loaded from a KMS, decrypted from an
// envelope, generated in-memory for tests) use this directly; the
// auth IdP wraps it with a store-backed LoadOrCreate.
func New(privateKey *rsa.PrivateKey, kid, issuer string, cfg Config) *Signer {
	if cfg.IDTokenTTL <= 0 {
		cfg.IDTokenTTL = DefaultIDTokenTTL
	}
	if cfg.FederationTokenTTL <= 0 {
		cfg.FederationTokenTTL = DefaultFederationTokenTTL
	}
	if cfg.ACRMFA == "" {
		cfg.ACRMFA = DefaultACRMFA
	}
	return &Signer{privateKey: privateKey, kid: kid, issuer: issuer, cfg: cfg}
}

// KID returns the active key identifier.
func (s *Signer) KID() string { return s.kid }

// PublicKey returns the active RSA public key.
func (s *Signer) PublicKey() *rsa.PublicKey { return &s.privateKey.PublicKey }

// MintFederationToken creates a signed RS256 JWT shaped for AWS STS
// `sts:AssumeRoleWithWebIdentity`. The `aud` value is set per role
// from the caller-supplied audience (matching the role trust policy's
// audience condition). Subject is the user UUID — AWS surfaces this
// as the `sub` claim that ends up in CloudTrail
// webIdFederationData.attributes.sub.
//
// principalTags is the **only** path by which user attributes reach
// AWS's policy-evaluation context as `aws:PrincipalTag/<key>`.
// Resource policies, permission policies, ABAC patterns — all consume
// these tags. Required prerequisite: the target role's trust policy
// must include `sts:TagSession` in Action.
//
// lifetime overrides Config.FederationTokenTTL when non-zero; the
// caller can pin a tighter window per call. Zero falls back to the
// configured default.
func (s *Signer) MintFederationToken(userID, audience, email, name string, groups, amr []string, authTime time.Time, lifetime time.Duration, principalTags map[string]string) (string, error) {
	now := time.Now().UTC()
	if lifetime <= 0 {
		lifetime = s.cfg.FederationTokenTTL
	}
	claims := FederationClaims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  gojwt.ClaimStrings{audience},
			ExpiresAt: gojwt.NewNumericDate(now.Add(lifetime)),
			IssuedAt:  gojwt.NewNumericDate(now),
			NotBefore: gojwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		Email:             email,
		Name:              name,
		PreferredUsername: email,
		Groups:            groups,
		AMR:               amr,
		AuthTime:          authTime.Unix(),
	}
	if len(principalTags) > 0 {
		// Deterministic key order keeps the JWT byte-stable for any
		// given input — important for cache hashing and test diff
		// readability.
		keys := make([]string, 0, len(principalTags))
		for k := range principalTags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pt := make(map[string][]string, len(principalTags))
		for _, k := range keys {
			pt[k] = []string{principalTags[k]}
		}
		claims.AWSTags = &awsclaims.PrincipalTagsValue{
			PrincipalTags:     pt,
			TransitiveTagKeys: keys,
		}
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.privateKey)
}

// MintIDToken creates a signed RS256 JWT ID token. sid (empty string
// accepted) is emitted as the OIDC Back-Channel Logout 1.0 `sid`
// claim and lets RPs correlate a logout_token back to a specific
// local session row. groups is emitted only when non-empty; callers
// gate this on the `groups` OAuth scope.
func (s *Signer) MintIDToken(userID, clientID, email, name, nonce string, scopes []string, mfaVerified bool, amr []string, authTime time.Time, sid string, groups []string) (string, error) {
	_ = scopes // reserved for future scope-driven claim selection
	now := time.Now().UTC()
	acr := ""
	if mfaVerified {
		acr = s.cfg.ACRMFA
	}
	claims := IDClaims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  gojwt.ClaimStrings{clientID},
			ExpiresAt: gojwt.NewNumericDate(now.Add(s.cfg.IDTokenTTL)),
			IssuedAt:  gojwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		Nonce:             nonce,
		AuthTime:          authTime.Unix(),
		ACR:               acr,
		AMR:               amr,
		SID:               sid,
		Email:             email,
		Name:              name,
		PreferredUsername: email,
		Groups:            groups,
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.privateKey)
}
