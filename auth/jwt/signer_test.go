package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return New(priv, "test-kid", "https://issuer.example", Config{})
}

// parseUnverified decodes the JWT header and claims without checking
// the signature — useful for asserting on the shape of what we minted.
func parseUnverified(t *testing.T, tok string) (header map[string]any, claims map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 segments: %d", len(parts))
	}
	decode := func(s string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("base64 decode: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}
		return m
	}
	return decode(parts[0]), decode(parts[1])
}

func TestSigner_KIDAndPublicKey(t *testing.T) {
	s := newTestSigner(t)
	if s.KID() != "test-kid" {
		t.Errorf("KID() = %q, want test-kid", s.KID())
	}
	pub := s.PublicKey()
	if pub == nil || pub.N == nil {
		t.Fatal("PublicKey returned nil or empty modulus")
	}
	if pub.N.BitLen() < 2040 {
		t.Errorf("public key bit length %d looks wrong for RSA-2048", pub.N.BitLen())
	}
}

func TestMintIDToken_ClaimsAndHeader(t *testing.T) {
	s := newTestSigner(t)
	authTime := time.Now().Add(-5 * time.Minute).UTC().Truncate(time.Second)

	tok, err := s.MintIDToken(
		"user-123", "client-abc", "alice@example.com", "Alice",
		"nonce-xyz", []string{"openid", "email"},
		true, []string{"pwd", "mfa"}, authTime, "sid-456",
		nil,
	)
	if err != nil {
		t.Fatalf("MintIDToken: %v", err)
	}

	header, claims := parseUnverified(t, tok)

	if header["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", header["alg"])
	}
	if header["kid"] != "test-kid" {
		t.Errorf("kid = %v, want test-kid", header["kid"])
	}

	wantStrings := map[string]string{
		"iss":                "https://issuer.example",
		"sub":                "user-123",
		"nonce":              "nonce-xyz",
		"sid":                "sid-456",
		"email":              "alice@example.com",
		"name":               "Alice",
		"preferred_username": "alice@example.com",
		"acr":                DefaultACRMFA,
	}
	for k, want := range wantStrings {
		if got, _ := claims[k].(string); got != want {
			t.Errorf("claim %q = %q, want %q", k, got, want)
		}
	}

	if at, ok := claims["auth_time"].(float64); !ok || int64(at) != authTime.Unix() {
		t.Errorf("auth_time = %v, want %d", claims["auth_time"], authTime.Unix())
	}

	amr, _ := claims["amr"].([]any)
	if len(amr) != 2 || amr[0] != "pwd" || amr[1] != "mfa" {
		t.Errorf("amr = %v, want [pwd mfa]", amr)
	}

	aud, _ := claims["aud"].([]any)
	if len(aud) != 1 || aud[0] != "client-abc" {
		t.Errorf("aud = %v, want [client-abc]", claims["aud"])
	}
}

func TestMintIDToken_NoMFAOmitsACR(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.MintIDToken("u", "c", "e@x", "", "", nil, false, nil, time.Now(), "", nil)
	if err != nil {
		t.Fatalf("MintIDToken: %v", err)
	}
	_, claims := parseUnverified(t, tok)
	if _, ok := claims["acr"]; ok {
		t.Errorf("acr should be omitted when mfaVerified=false, got %v", claims["acr"])
	}
	if _, ok := claims["sid"]; ok {
		t.Errorf("sid should be omitted when empty, got %v", claims["sid"])
	}
	if _, ok := claims["nonce"]; ok {
		t.Errorf("nonce should be omitted when empty, got %v", claims["nonce"])
	}
}

// TestMintIDToken_GroupsClaim pins the emit/omit contract on the
// groups claim: present-when-passed, absent-when-empty. The caller
// gates this on the `groups` OAuth scope.
func TestMintIDToken_GroupsClaim(t *testing.T) {
	s := newTestSigner(t)

	withGroups, err := s.MintIDToken("u", "c", "e@x", "", "", []string{"openid"},
		false, nil, time.Now(), "", []string{"platform", "data"})
	if err != nil {
		t.Fatalf("MintIDToken (with groups): %v", err)
	}
	_, claims := parseUnverified(t, withGroups)
	got, ok := claims["groups"].([]any)
	if !ok {
		t.Fatalf("groups claim missing or wrong type: %v", claims["groups"])
	}
	if len(got) != 2 || got[0] != "platform" || got[1] != "data" {
		t.Errorf("groups = %v, want [platform data]", got)
	}

	withoutGroups, err := s.MintIDToken("u", "c", "e@x", "", "", []string{"openid"},
		false, nil, time.Now(), "", nil)
	if err != nil {
		t.Fatalf("MintIDToken (no groups): %v", err)
	}
	_, claims = parseUnverified(t, withoutGroups)
	if _, present := claims["groups"]; present {
		t.Errorf("groups claim should be omitted when nil, got %v", claims["groups"])
	}
}

func TestMintIDToken_SignatureVerifies(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.MintIDToken("u", "c", "e@x", "n", "", nil, true, nil, time.Now(), "", nil)
	if err != nil {
		t.Fatalf("MintIDToken: %v", err)
	}
	parsed, err := gojwt.Parse(tok, func(_ *gojwt.Token) (any, error) { return s.PublicKey(), nil })
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Valid {
		t.Error("parsed token reports invalid")
	}
}

// TestConfig_OverridesACR pins the lifted-policy contract: callers
// who pass a Config with a custom ACRMFA see that string in the acr
// claim instead of the package default.
func TestConfig_OverridesACR(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := New(priv, "kid", "https://issuer.example", Config{ACRMFA: "custom:acr:high"})
	tok, err := s.MintIDToken("u", "c", "e@x", "", "", nil, true, nil, time.Now(), "", nil)
	if err != nil {
		t.Fatalf("MintIDToken: %v", err)
	}
	_, claims := parseUnverified(t, tok)
	if claims["acr"] != "custom:acr:high" {
		t.Errorf("acr = %v, want custom:acr:high", claims["acr"])
	}
}

// TestConfig_OverridesIDTokenTTL pins the lifted-policy contract for
// ID token lifetime — operators tuning the TTL via Config see exp-iat
// match their input.
func TestConfig_OverridesIDTokenTTL(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := New(priv, "kid", "https://issuer.example", Config{IDTokenTTL: 5 * time.Minute})
	tok, err := s.MintIDToken("u", "c", "e@x", "", "", nil, false, nil, time.Now(), "", nil)
	if err != nil {
		t.Fatalf("MintIDToken: %v", err)
	}
	_, claims := parseUnverified(t, tok)
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if int(exp-iat) != 300 {
		t.Errorf("exp - iat = %d, want 300 (5min)", int(exp-iat))
	}
}

func TestMintLogoutToken_Shape(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now().UTC().Truncate(time.Second)
	tok, err := s.MintLogoutToken("rp-aud", "user-7", "sid-7", "jti-7", now)
	if err != nil {
		t.Fatalf("MintLogoutToken: %v", err)
	}

	header, claims := parseUnverified(t, tok)
	if header["kid"] != "test-kid" {
		t.Errorf("kid = %v, want test-kid", header["kid"])
	}
	if claims["iss"] != "https://issuer.example" {
		t.Errorf("iss = %v, want https://issuer.example", claims["iss"])
	}
	if claims["sub"] != "user-7" {
		t.Errorf("sub = %v, want user-7", claims["sub"])
	}
	if claims["sid"] != "sid-7" {
		t.Errorf("sid = %v, want sid-7", claims["sid"])
	}
	if claims["jti"] != "jti-7" {
		t.Errorf("jti = %v, want jti-7", claims["jti"])
	}
	if _, ok := claims["nonce"]; ok {
		t.Error("logout_token MUST NOT contain a nonce claim (spec §2.6)")
	}

	events, ok := claims["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim is not an object: %T", claims["events"])
	}
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Errorf("missing backchannel-logout event member: %v", events)
	}

	if iat, ok := claims["iat"].(float64); !ok || int64(iat) != now.Unix() {
		t.Errorf("iat = %v, want %d", claims["iat"], now.Unix())
	}
	if exp, ok := claims["exp"].(float64); !ok || int64(exp) != now.Add(2*time.Minute).Unix() {
		t.Errorf("exp = %v, want iat + 2m", claims["exp"])
	}
}

func TestMintFederationToken_ClaimsAndAudience(t *testing.T) {
	s := newTestSigner(t)
	authTime := time.Now().Add(-2 * time.Minute).UTC().Truncate(time.Second)
	tok, err := s.MintFederationToken(
		"user-uuid", "tokyo3-platform-prod",
		"alice@example.com", "Alice",
		[]string{"platform", "everyone"},
		[]string{"pwd", "mfa"},
		authTime, 5*time.Minute,
		nil, // no principal_tags in this test
	)
	if err != nil {
		t.Fatalf("MintFederationToken: %v", err)
	}
	header, claims := parseUnverified(t, tok)
	if header["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", header["alg"])
	}
	if header["kid"] != "test-kid" {
		t.Errorf("kid = %v, want test-kid", header["kid"])
	}
	if claims["iss"] != "https://issuer.example" {
		t.Errorf("iss = %v, want https://issuer.example", claims["iss"])
	}
	if claims["sub"] != "user-uuid" {
		t.Errorf("sub = %v, want user-uuid", claims["sub"])
	}
	aud, _ := claims["aud"].([]any)
	if len(aud) != 1 || aud[0] != "tokyo3-platform-prod" {
		t.Errorf("aud = %v, want [tokyo3-platform-prod]", claims["aud"])
	}
	if got, _ := claims["email"].(string); got != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", got)
	}
	groups, _ := claims["groups"].([]any)
	if len(groups) != 2 || groups[0] != "platform" || groups[1] != "everyone" {
		t.Errorf("groups = %v, want [platform everyone]", groups)
	}
	if at, ok := claims["auth_time"].(float64); !ok || int64(at) != authTime.Unix() {
		t.Errorf("auth_time = %v, want %d", claims["auth_time"], authTime.Unix())
	}
	// Lifetime check: exp - iat ≈ 5 minutes.
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if int(exp-iat) != 300 {
		t.Errorf("exp - iat = %d, want 300 (5 minutes)", int(exp-iat))
	}
	if _, ok := claims["https://aws.amazon.com/tags"]; ok {
		t.Error("https://aws.amazon.com/tags should be absent when principalTags is nil")
	}
}

func TestMintFederationToken_DefaultLifetime(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.MintFederationToken("u", "aud", "e@x", "N", nil, nil, time.Now(), 0, nil)
	if err != nil {
		t.Fatalf("MintFederationToken: %v", err)
	}
	_, claims := parseUnverified(t, tok)
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if int(exp-iat) != int(DefaultFederationTokenTTL.Seconds()) {
		t.Errorf("default lifetime = %d, want %d", int(exp-iat), int(DefaultFederationTokenTTL.Seconds()))
	}
}

func TestMintFederationToken_SignatureVerifies(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.MintFederationToken("u", "aud", "", "", nil, nil, time.Now(), time.Minute, nil)
	if err != nil {
		t.Fatalf("MintFederationToken: %v", err)
	}
	parsed, err := gojwt.Parse(tok, func(_ *gojwt.Token) (any, error) { return s.PublicKey(), nil })
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Valid {
		t.Error("parsed token reports invalid")
	}
}

// TestMintFederationToken_AWSPrincipalTagsClaim asserts the exact
// wire shape of the AWS session-tags claim. Format is constrained by
// AWS — claim name must equal awsclaims.PrincipalTagsClaim verbatim,
// principal_tags values must be list-of-strings, transitive_tag_keys
// lists every key that should persist through role chaining.
func TestMintFederationToken_AWSPrincipalTagsClaim(t *testing.T) {
	s := newTestSigner(t)
	tags := map[string]string{
		"sub":   "alice-uuid",
		"email": "alice@example.com",
		"team":  "platform",
	}
	tok, err := s.MintFederationToken(
		"alice-uuid", "tokyo3-platform-prod",
		"alice@example.com", "Alice",
		nil, []string{"pwd", "mfa"},
		time.Now(), time.Minute,
		tags,
	)
	if err != nil {
		t.Fatalf("MintFederationToken: %v", err)
	}
	_, claims := parseUnverified(t, tok)
	rawTags, ok := claims["https://aws.amazon.com/tags"]
	if !ok {
		t.Fatal("https://aws.amazon.com/tags claim missing")
	}
	tagsObj, ok := rawTags.(map[string]any)
	if !ok {
		t.Fatalf("tags claim is not an object: %T", rawTags)
	}
	pt, ok := tagsObj["principal_tags"].(map[string]any)
	if !ok {
		t.Fatalf("principal_tags is not an object: %T", tagsObj["principal_tags"])
	}
	for k, want := range tags {
		got, ok := pt[k].([]any)
		if !ok {
			t.Errorf("principal_tags[%q] is not a list: %T", k, pt[k])
			continue
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("principal_tags[%q] = %v, want [%q]", k, got, want)
		}
	}
	// transitive_tag_keys must list every key, sorted (deterministic).
	transRaw, ok := tagsObj["transitive_tag_keys"].([]any)
	if !ok {
		t.Fatalf("transitive_tag_keys is not a list: %T", tagsObj["transitive_tag_keys"])
	}
	wantTrans := []string{"email", "sub", "team"} // alphabetical
	if len(transRaw) != len(wantTrans) {
		t.Fatalf("transitive_tag_keys len = %d, want %d", len(transRaw), len(wantTrans))
	}
	for i, want := range wantTrans {
		if transRaw[i] != want {
			t.Errorf("transitive_tag_keys[%d] = %v, want %q (sorted order required for deterministic JWT)", i, transRaw[i], want)
		}
	}
}

// TestMintFederationToken_EmptyTagsOmitsClaim guards the "omitempty"
// behavior — passing an empty map (not nil) must still omit the claim
// so AWS doesn't reject the call when sts:TagSession isn't authorised.
func TestMintFederationToken_EmptyTagsOmitsClaim(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.MintFederationToken("u", "aud", "", "", nil, nil, time.Now(), time.Minute, map[string]string{})
	if err != nil {
		t.Fatalf("MintFederationToken: %v", err)
	}
	_, claims := parseUnverified(t, tok)
	if _, ok := claims["https://aws.amazon.com/tags"]; ok {
		t.Error("empty tags map should omit the AWS tags claim")
	}
}

func TestMintLogoutToken_AutoJTI(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.MintLogoutToken("rp", "u", "", "", time.Now())
	if err != nil {
		t.Fatalf("MintLogoutToken: %v", err)
	}
	_, claims := parseUnverified(t, tok)
	jti, _ := claims["jti"].(string)
	if jti == "" {
		t.Error("empty jti was not auto-populated")
	}
	if _, ok := claims["sid"]; ok {
		t.Error("empty sid should be omitted")
	}
}

func TestPublicKeyToJWK(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk := PublicKeyToJWK(&priv.PublicKey, "kid-1")

	if jwk.KTY != "RSA" || jwk.USE != "sig" || jwk.ALG != "RS256" || jwk.KID != "kid-1" {
		t.Errorf("metadata mismatch: %+v", jwk)
	}

	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("decode N: %v", err)
	}
	if new(big.Int).SetBytes(n).Cmp(priv.PublicKey.N) != 0 {
		t.Error("decoded N does not match original modulus")
	}

	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Fatalf("decode E: %v", err)
	}
	if int(new(big.Int).SetBytes(e).Int64()) != priv.PublicKey.E {
		t.Errorf("decoded E = %d, want %d", new(big.Int).SetBytes(e).Int64(), priv.PublicKey.E)
	}
}
