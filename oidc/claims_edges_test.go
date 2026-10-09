package oidc_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/oidc"
)

// An ID token whose claims do not decode into the expected types is refused,
// even though its signature and standard claims are valid.
func TestHTTPVerifier_Verify_RejectsUndecodableClaims(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if err != nil {
		t.Fatalf("NewHTTPVerifier: %v", err)
	}
	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{
		"iss": fi.issuer, "aud": testAud, "sub": "user-1",
		"iat": now, "exp": now + 300,
		"email": 42, // a string claim with a number value
	})
	if claims, err := ver.Verify(context.Background(), tok); err == nil {
		t.Fatalf("Verify accepted undecodable claims: %+v", claims)
	}
}

// auth_time is the authentication instant that session-freshness checks depend
// on. It must reach the verified claims unchanged.
func TestHTTPVerifier_Verify_CarriesAuthTime(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if err != nil {
		t.Fatalf("NewHTTPVerifier: %v", err)
	}
	now := time.Now().Unix()
	authAt := now - 120
	tok := fi.signToken(t, map[string]any{
		"iss": fi.issuer, "aud": testAud, "sub": "user-1",
		"iat": now, "exp": now + 300,
		"auth_time": authAt,
	})
	claims, err := ver.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !claims.AuthTime.Equal(time.Unix(authAt, 0)) {
		t.Errorf("AuthTime = %v, want %v", claims.AuthTime, time.Unix(authAt, 0).UTC())
	}
}

// logoutToken signs a backchannel logout token. The claims map overrides the
// valid defaults, so a test can break one field at a time.
func logoutToken(fi *fakeIssuer, t *testing.T, overrides map[string]any) string {
	t.Helper()
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": fi.issuer, "aud": testAud, "sub": "user-1",
		"iat": now, "exp": now + 300,
		"sid": "session-1", "jti": "jti-1",
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	return fi.signToken(t, claims)
}

// A logout token has no session of its own to revoke without a jti, so it is
// refused rather than applied without replay protection.
func TestVerifyLogoutToken_RejectsMissingJTI(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if err != nil {
		t.Fatalf("NewHTTPVerifier: %v", err)
	}
	tok := logoutToken(fi, t, map[string]any{"jti": nil})
	if claims, err := ver.VerifyLogoutToken(context.Background(), tok); err == nil {
		t.Fatalf("logout token without jti accepted: %+v", claims)
	}
}

// Logout claims that do not decode into the expected types are refused.
func TestVerifyLogoutToken_RejectsUndecodableClaims(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if err != nil {
		t.Fatalf("NewHTTPVerifier: %v", err)
	}
	// sid must be a string. The JWT library does not check it, so the logout
	// decode is what refuses it.
	tok := logoutToken(fi, t, map[string]any{"sid": 42})
	if claims, err := ver.VerifyLogoutToken(context.Background(), tok); err == nil {
		t.Fatalf("logout token with a numeric sid accepted: %+v", claims)
	}
}

// A lazily discovered verifier reports a failed discovery when asked to verify
// a logout token. It must not treat the token as checked.
func TestLazyVerifier_VerifyLogoutTokenSurfacesDiscoveryFailure(t *testing.T) {
	v, err := oidc.NewLazyHTTPVerifier("http://127.0.0.1:1", testAud)
	if err != nil {
		t.Fatalf("NewLazyHTTPVerifier: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if claims, err := v.VerifyLogoutToken(ctx, "a.b.c"); err == nil {
		t.Fatalf("VerifyLogoutToken with no issuer reachable = %+v, want an error", claims)
	}
}

// nbf is not checked by the JWT library, so the logout verifier must parse it
// itself. A value that is not a numeric date, or is null, is refused.
func TestVerifyLogoutToken_RejectsMalformedNotBefore(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if err != nil {
		t.Fatalf("NewHTTPVerifier: %v", err)
	}
	for name, nbf := range map[string]any{
		"not a number": "soon",
		"null":         json.RawMessage("null"), // a real JSON null; nil would delete the claim
	} {
		t.Run(name, func(t *testing.T) {
			tok := logoutToken(fi, t, map[string]any{"nbf": nbf})
			if claims, err := ver.VerifyLogoutToken(context.Background(), tok); err == nil {
				t.Fatalf("logout token with nbf %v accepted: %+v", nbf, claims)
			}
		})
	}
}

// A valid nbf in the past is accepted. A nbf in the future is refused, since
// the token is not yet valid.
func TestVerifyLogoutToken_NotBeforeWindow(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if err != nil {
		t.Fatalf("NewHTTPVerifier: %v", err)
	}
	past := time.Now().Add(-time.Minute).Unix()
	future := time.Now().Add(time.Hour).Unix()

	if _, err := ver.VerifyLogoutToken(context.Background(), logoutToken(fi, t, map[string]any{"nbf": past})); err != nil {
		t.Errorf("logout token with a past nbf rejected: %v", err)
	}
	if claims, err := ver.VerifyLogoutToken(context.Background(), logoutToken(fi, t, map[string]any{"nbf": future})); err == nil {
		t.Errorf("logout token not valid until later was accepted: %+v", claims)
	}
}
