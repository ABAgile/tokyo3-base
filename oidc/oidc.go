// Package oidc verifies inbound OIDC ID tokens — minted by whatever OIDC IdP
// the operator configures — so a service can derive a caller's identity and
// groups from a cryptographically-signed assertion rather than a self-declared
// request field.
//
// Consumers talk to the small [TokenVerifier] interface so tests can inject a
// deterministic stub instead of a real issuer. The production implementation
// ([HTTPVerifier]) wraps github.com/coreos/go-oidc/v3, which handles the OIDC
// discovery doc and JWKS fetch/refresh; [LazyVerifier] defers that I/O to the
// first Verify call so a service can boot while its IdP is briefly unreachable
// and self-heal once it returns.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"sync"

	goidc "github.com/coreos/go-oidc/v3/oidc"
)

// Claims is the subset of OIDC + custom claims services typically read. New
// fields are additive; downstream code reads through this struct so claim
// renames in the underlying token format are absorbed here.
type Claims struct {
	// Subject is the OIDC `sub` claim — the stable user identifier from the
	// IdP (typically a UUID).
	Subject string
	// Email is the verified email of the user, when the IdP surfaces it.
	Email string
	// Name is the user's display name, when present.
	Name string
	// Groups is the authoritative group-membership list. The IdP derives this
	// from its own group/SCIM records.
	Groups []string
	// Nonce echoes the `nonce` the relying party sent on the authorize request
	// — bound into the ID token by the IdP. Empty unless the caller requested
	// one. A browser login checks it against the value stashed in its flow
	// cookie to defend against token replay; a machine bearer-token path
	// leaves it unset.
	Nonce string
}

// TokenVerifier is the abstraction services talk to. Implementations must
// validate signature, issuer, audience, and expiry, and return [Claims] only
// for fully-validated tokens.
type TokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*Claims, error)
}

// HTTPVerifier wraps go-oidc with discovery + JWKS auto-refresh. Built for a
// single (issuer, audience) pair; create a separate instance per IdP cluster
// the service should trust.
type HTTPVerifier struct {
	verifier *goidc.IDTokenVerifier
	issuer   string
	audience string
}

// NewHTTPVerifier discovers issuer's OIDC metadata, fetches its JWKS, and
// returns a verifier configured for audience. The returned verifier
// transparently refreshes the JWKS when the IdP rotates keys — no manual
// reload needed.
//
// issuer is the IdP's public issuer URL (e.g. "https://auth.example.com").
// audience matches the `aud` claim on every token the IdP issues for this
// service.
//
// Errors here mean the issuer is unreachable, the discovery doc is malformed,
// or the JWKS can't be fetched — surface them as fatal startup errors, or use
// [NewLazyHTTPVerifier] to defer them to the first request.
func NewHTTPVerifier(ctx context.Context, issuer, audience string) (*HTTPVerifier, error) {
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if audience == "" {
		return nil, errors.New("audience is required")
	}
	provider, err := goidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider %q: %w", issuer, err)
	}
	v := provider.Verifier(&goidc.Config{ClientID: audience})
	return &HTTPVerifier{verifier: v, issuer: issuer, audience: audience}, nil
}

// Verify satisfies [TokenVerifier]. Returns the underlying go-oidc errors;
// callers should treat any error as a 401.
func (v *HTTPVerifier) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	if rawIDToken == "" {
		return nil, errors.New("empty token")
	}
	tok, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Email  string   `json:"email"`
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
		Nonce  string   `json:"nonce"`
	}
	if err := tok.Claims(&raw); err != nil {
		return nil, fmt.Errorf("decode token claims: %w", err)
	}
	return &Claims{
		Subject: tok.Subject,
		Email:   raw.Email,
		Name:    raw.Name,
		Groups:  raw.Groups,
		Nonce:   raw.Nonce,
	}, nil
}

// Issuer and Audience expose the configured pair so callers can include them
// in /healthz and audit events for operator visibility.
func (v *HTTPVerifier) Issuer() string   { return v.issuer }
func (v *HTTPVerifier) Audience() string { return v.audience }

// LazyVerifier defers OIDC discovery + JWKS fetch to the first
// [LazyVerifier.Verify] call. This decouples a service's startup from the
// IdP's reachability: the service can boot when the IdP is down, and the first
// request after it returns succeeds. Discovery failures bubble up as ordinary
// verification errors (map them to 401), and the next request retries — so a
// transient IdP outage at boot is self-healing.
type LazyVerifier struct {
	issuer, audience string

	mu       sync.Mutex
	verifier *HTTPVerifier
}

// NewLazyHTTPVerifier returns a verifier that performs no I/O at construction.
// The (issuer, audience) pair is validated immediately — same shape as
// [NewHTTPVerifier] — but the network round-trip to the issuer is deferred to
// the first [LazyVerifier.Verify] call.
func NewLazyHTTPVerifier(issuer, audience string) (*LazyVerifier, error) {
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if audience == "" {
		return nil, errors.New("audience is required")
	}
	return &LazyVerifier{issuer: issuer, audience: audience}, nil
}

// Verify satisfies [TokenVerifier]. On the first call it performs OIDC
// discovery against the configured issuer; if discovery fails (e.g. the IdP is
// unreachable) the error is returned and the next call retries. Once discovery
// succeeds the resolved [HTTPVerifier] is cached for the process lifetime.
func (v *LazyVerifier) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	hv, err := v.ensure(ctx)
	if err != nil {
		return nil, err
	}
	return hv.Verify(ctx, rawIDToken)
}

func (v *LazyVerifier) ensure(ctx context.Context) (*HTTPVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}
	hv, err := NewHTTPVerifier(ctx, v.issuer, v.audience)
	if err != nil {
		return nil, err
	}
	v.verifier = hv
	return hv, nil
}

func (v *LazyVerifier) Issuer() string   { return v.issuer }
func (v *LazyVerifier) Audience() string { return v.audience }
