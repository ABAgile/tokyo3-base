package oidc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/oidc"
)

func TestVerifyLogoutToken_ClaimValidation(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"optional expiry omitted", func(c map[string]any) { delete(c, "exp") }, ""},
		{"empty nonce", func(c map[string]any) { c["nonce"] = "" }, "nonce"},
		{"null nonce", func(c map[string]any) { c["nonce"] = nil }, "nonce"},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }, "iat"},
		{"null iat", func(c map[string]any) { c["iat"] = nil }, "unmarshal claims"},
		{"future iat", func(c map[string]any) { c["iat"] = now + 60 }, "iat"},
		{"stale iat", func(c map[string]any) { c["iat"] = now - 360 }, "iat"},
		{"expired", func(c map[string]any) { c["exp"] = now - 120 }, "exp"},
		{"slightly future iat within skew", func(c map[string]any) { c["iat"] = now + 10 }, ""},
		{"just expired within skew", func(c map[string]any) { c["exp"] = now - 5 }, ""},
		{"slightly future nbf within skew", func(c map[string]any) { c["nbf"] = now + 10 }, ""},
		{"null expiry", func(c map[string]any) { c["exp"] = nil }, "unmarshal claims"},
		{"future nbf", func(c map[string]any) { c["nbf"] = now + 60 }, "nbf"},
		{"null nbf", func(c map[string]any) { c["nbf"] = nil }, "nbf"},
		{"past nbf", func(c map[string]any) { c["nbf"] = now - 1 }, ""},
		{"null event", func(c map[string]any) {
			c["events"] = map[string]any{"http://schemas.openid.net/event/backchannel-logout": nil}
		}, "empty object"},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://other.example" }, "different provider"},
		{"wrong audience", func(c map[string]any) { c["aud"] = "other-client" }, "audience"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"iss": fi.issuer, "aud": testAud, "sid": "s", "jti": tc.name,
				"iat": now, "exp": now + 300,
				"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
			}
			tc.mutate(body)
			raw := fi.signToken(t, body)
			claims, err := ver.VerifyLogoutToken(context.Background(), raw)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("VerifyLogoutToken = %+v, %v, want error containing %q", claims, err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, present := body["exp"]; !present && !claims.ExpiresAt.IsZero() {
				t.Fatalf("absent exp returned ExpiresAt = %v", claims.ExpiresAt)
			}
			if wantIAT, _ := body["iat"].(int64); claims.IssuedAt.Unix() != wantIAT {
				t.Fatalf("IssuedAt = %v", claims.IssuedAt)
			}
		})
	}
}

func TestVerifyLogoutToken_RejectsTamperedSignatureWithoutExpiry(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"iss": fi.issuer, "aud": testAud, "sub": "user", "jti": "j", "iat": time.Now().Unix(),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	raw := fi.signToken(t, body)
	parts := strings.Split(raw, ".")
	parts[2] = b64url(make([]byte, 256))
	if _, err := ver.VerifyLogoutToken(context.Background(), strings.Join(parts, ".")); err == nil {
		t.Fatal("accepted tampered signature")
	}
	// The separate logout verifier must not relax expiry checks for ID tokens.
	if _, err := ver.Verify(context.Background(), raw); err == nil {
		t.Fatal("ID-token verifier accepted a token without exp")
	}
}

// A logout_token shares keys, issuer and audience with ID tokens and may carry
// exp, so Verify must refuse it rather than treat it as proof of identity.
func TestHTTPVerifier_Verify_RejectsLogoutToken(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	raw := fi.signToken(t, map[string]any{
		"iss": fi.issuer, "aud": testAud, "sub": "u1", "sid": "s", "jti": "j",
		"iat": now, "exp": now + 300,
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	})
	if claims, err := ver.Verify(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "logout_token") {
		t.Fatalf("Verify = %+v, %v, want logout_token rejection", claims, err)
	}
}
