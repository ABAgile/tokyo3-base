package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/oidc"
)

const testAud = "test-svc"

// fakeIssuer is a minimal in-process OIDC issuer that serves the metadata +
// JWKS documents [oidc.HTTPVerifier] needs, and signs tokens with a matching
// RSA key.
type fakeIssuer struct {
	server  *httptest.Server
	priv    *rsa.PrivateKey
	kid     string
	issuer  string
	jwksURL string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	fi := &fakeIssuer{priv: priv, kid: "test-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", fi.handleDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", fi.handleJWKS)
	fi.server = httptest.NewServer(mux)
	fi.issuer = fi.server.URL
	fi.jwksURL = fi.server.URL + "/.well-known/jwks.json"
	t.Cleanup(fi.server.Close)
	return fi
}

func (fi *fakeIssuer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                fi.issuer,
		"jwks_uri":                              fi.jwksURL,
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (fi *fakeIssuer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": fi.kid,
				"alg": "RS256",
				"use": "sig",
				"n":   b64url(fi.priv.N.Bytes()),
				"e":   b64url(intToBytes(fi.priv.E)),
			},
		},
	})
}

// signToken builds an RS256-signed JWT with the given claims and the issuer's
// signing key. Caller fills iss/aud/exp/iat so tests can exercise each
// validation path.
func (fi *fakeIssuer) signToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": fi.kid, "typ": "JWT"}
	hdrJSON, _ := json.Marshal(header)
	payJSON, _ := json.Marshal(claims)
	signingInput := b64url(hdrJSON) + "." + b64url(payJSON)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, fi.priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signingInput + "." + b64url(sig)
}

// b64url is JWS-flavored base64 (URL-safe, no padding).
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// intToBytes returns the minimal big-endian byte slice for e — RSA public
// exponents are conventionally small (65537 = 0x010001).
func intToBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	for i, x := range b {
		if x != 0 {
			return b[i:]
		}
	}
	return b[:]
}

// ── tests ───────────────────────────────────────────────────────────────────

func TestNewHTTPVerifier_RejectsEmptyArgs(t *testing.T) {
	if _, err := oidc.NewHTTPVerifier(context.Background(), "", testAud); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Errorf("empty issuer: err = %v, want 'issuer'", err)
	}
	if _, err := oidc.NewHTTPVerifier(context.Background(), "https://example.com", ""); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Errorf("empty audience: err = %v, want 'audience'", err)
	}
}

func TestHTTPVerifier_Verify_HappyPath(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if err != nil {
		t.Fatalf("NewHTTPVerifier: %v", err)
	}
	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{
		"iss": fi.issuer, "aud": testAud, "sub": "user-uuid-123",
		"email": "alice@example.com", "name": "Alice",
		"groups": []string{"eng", "sre"}, "nonce": "n-1",
		"iat": now, "exp": now + 300,
	})
	claims, err := ver.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-uuid-123" || claims.Email != "alice@example.com" || claims.Name != "Alice" || claims.Nonce != "n-1" {
		t.Errorf("claims = %+v", claims)
	}
	if want := []string{"eng", "sre"}; fmt.Sprint(claims.Groups) != fmt.Sprint(want) {
		t.Errorf("Groups = %v, want %v", claims.Groups, want)
	}
}

func TestHTTPVerifier_Verify_RejectsExpiredToken(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{"iss": fi.issuer, "aud": testAud, "sub": "u", "iat": now - 3600, "exp": now - 300})
	if _, err := ver.Verify(context.Background(), tok); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("err = %v, want 'expired'", err)
	}
}

func TestHTTPVerifier_Verify_RejectsWrongAudience(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{"iss": fi.issuer, "aud": "some-other-app", "sub": "u", "iat": now, "exp": now + 300})
	if _, err := ver.Verify(context.Background(), tok); err == nil || !strings.Contains(strings.ToLower(err.Error()), "audience") {
		t.Errorf("err = %v, want 'audience'", err)
	}
}

func TestHTTPVerifier_Verify_RejectsWrongIssuer(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{"iss": "https://attacker.example.com", "aud": testAud, "sub": "u", "iat": now, "exp": now + 300})
	if _, err := ver.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestHTTPVerifier_Verify_RejectsBadSignature(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{"iss": fi.issuer, "aud": testAud, "sub": "u", "iat": now, "exp": now + 300})
	parts := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[len(sig)-1] ^= 0xff
	parts[2] = b64url(sig)
	if _, err := ver.Verify(context.Background(), strings.Join(parts, ".")); err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestHTTPVerifier_Verify_RejectsEmptyToken(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if _, err := ver.Verify(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("err = %v, want 'empty'", err)
	}
}

func TestHTTPVerifier_IssuerAudienceAccessors(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if ver.Issuer() != fi.issuer || ver.Audience() != testAud {
		t.Errorf("accessors = %q/%q", ver.Issuer(), ver.Audience())
	}
}

// ── LazyVerifier ──────────────────────────────────────────────────────────────

func TestNewLazyHTTPVerifier_RejectsEmptyArgs(t *testing.T) {
	if _, err := oidc.NewLazyHTTPVerifier("", testAud); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Errorf("empty issuer: err = %v", err)
	}
	if _, err := oidc.NewLazyHTTPVerifier("https://example.com", ""); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Errorf("empty audience: err = %v", err)
	}
}

func TestNewLazyHTTPVerifier_NoDialOnConstruction(t *testing.T) {
	// Construction must succeed against an unreachable issuer — the whole
	// point is that a service boots even when its IdP is down.
	v, err := oidc.NewLazyHTTPVerifier("http://127.0.0.1:1", testAud)
	if err != nil {
		t.Fatalf("construction must not dial: %v", err)
	}
	if v.Issuer() != "http://127.0.0.1:1" || v.Audience() != testAud {
		t.Errorf("accessors = %q/%q", v.Issuer(), v.Audience())
	}
}

func TestLazyVerifier_DiscoveryDeferredAndCached(t *testing.T) {
	var hits int32
	fi := newCountingIssuer(t, &hits, nil)
	ver, err := oidc.NewLazyHTTPVerifier(fi.issuer, testAud)
	if err != nil {
		t.Fatalf("NewLazyHTTPVerifier: %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("discovery hit on construction: %d", hits)
	}
	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{"iss": fi.issuer, "aud": testAud, "sub": "u", "iat": now, "exp": now + 300})
	for i := range 2 {
		if _, err := ver.Verify(context.Background(), tok); err != nil {
			t.Fatalf("Verify #%d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("discovery hits = %d, want 1 (deferred once, then cached)", got)
	}
}

func newCountingIssuer(t *testing.T, hits *int32, shouldFail func() bool) *fakeIssuer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	fi := &fakeIssuer{priv: priv, kid: "test-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		if shouldFail != nil && shouldFail() {
			http.Error(w, "issuer unreachable", http.StatusServiceUnavailable)
			return
		}
		fi.handleDiscovery(w, r)
	})
	mux.HandleFunc("/.well-known/jwks.json", fi.handleJWKS)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	fi.server, fi.issuer, fi.jwksURL = srv, srv.URL, srv.URL+"/.well-known/jwks.json"
	return fi
}

func TestLazyVerifier_DiscoveryFailureRetries(t *testing.T) {
	var hits int32
	failFirst := int32(1)
	fi := newCountingIssuer(t, &hits, func() bool { return atomic.LoadInt32(&failFirst) == 1 })
	ver, err := oidc.NewLazyHTTPVerifier(fi.issuer, testAud)
	if err != nil {
		t.Fatalf("NewLazyHTTPVerifier: %v", err)
	}
	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{"iss": fi.issuer, "aud": testAud, "sub": "u", "iat": now, "exp": now + 300})
	if _, err := ver.Verify(context.Background(), tok); err == nil {
		t.Fatal("first Verify must fail while issuer returns 503")
	}
	atomic.StoreInt32(&failFirst, 0)
	if _, err := ver.Verify(context.Background(), tok); err != nil {
		t.Fatalf("second Verify after issuer recovered: %v", err)
	}
}

// stubVerifier shows TokenVerifier is implementable without a live IdP — the
// seam the upcoming login flow and tests depend on.
type stubVerifier struct{ claims *oidc.Claims }

func (s stubVerifier) Verify(context.Context, string) (*oidc.Claims, error) { return s.claims, nil }

func TestTokenVerifier_Stub(t *testing.T) {
	var v oidc.TokenVerifier = stubVerifier{claims: &oidc.Claims{Subject: "u-1"}}
	if got, err := v.Verify(context.Background(), "tok"); err != nil || got.Subject != "u-1" {
		t.Fatalf("stub = %+v, %v", got, err)
	}
}

func TestVerifyLogoutToken(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, testAud)
	if err != nil {
		t.Fatalf("NewHTTPVerifier: %v", err)
	}

	now := time.Now().Unix()
	validLogoutToken := fi.signToken(t, map[string]any{
		"iss": fi.issuer,
		"aud": testAud,
		"sub": "user-1",
		"iat": now,
		"exp": now + 300,
		"sid": "session-1",
		"jti": "jti-1",
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	})

	claims, err := ver.VerifyLogoutToken(context.Background(), validLogoutToken)
	if err != nil {
		t.Fatalf("VerifyLogoutToken failed: %v", err)
	}
	if claims.Subject != "user-1" || claims.SessionID != "session-1" || claims.JTI != "jti-1" {
		t.Errorf("unexpected logout claims: %+v", claims)
	}

	// Verify using LazyVerifier as well to exercise and verify it
	lazyVer, err := oidc.NewLazyHTTPVerifier(fi.issuer, testAud)
	if err != nil {
		t.Fatalf("NewLazyHTTPVerifier: %v", err)
	}
	lazyClaims, err := lazyVer.VerifyLogoutToken(context.Background(), validLogoutToken)
	if err != nil {
		t.Fatalf("LazyVerifier.VerifyLogoutToken failed: %v", err)
	}
	if lazyClaims.Subject != "user-1" || lazyClaims.SessionID != "session-1" {
		t.Errorf("unexpected lazy logout claims: %+v", lazyClaims)
	}

	// Nonce is forbidden
	invalidNonceToken := fi.signToken(t, map[string]any{
		"iss":   fi.issuer,
		"aud":   testAud,
		"sub":   "user-1",
		"iat":   now,
		"exp":   now + 300,
		"sid":   "session-1",
		"jti":   "jti-1",
		"nonce": "some-nonce",
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	})
	if _, err := ver.VerifyLogoutToken(context.Background(), invalidNonceToken); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Errorf("expected nonce error, got %v", err)
	}

	// Missing backchannel-logout event
	missingEventToken := fi.signToken(t, map[string]any{
		"iss":    fi.issuer,
		"aud":    testAud,
		"sub":    "user-1",
		"iat":    now,
		"exp":    now + 300,
		"sid":    "session-1",
		"jti":    "jti-1",
		"events": map[string]any{},
	})
	if _, err := ver.VerifyLogoutToken(context.Background(), missingEventToken); err == nil || !strings.Contains(err.Error(), "missing backchannel-logout event") {
		t.Errorf("expected missing event error, got %v", err)
	}

	// Missing both sub and sid
	missingSubSidToken := fi.signToken(t, map[string]any{
		"iss": fi.issuer,
		"aud": testAud,
		"iat": now,
		"exp": now + 300,
		"jti": "jti-1",
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	})
	if _, err := ver.VerifyLogoutToken(context.Background(), missingSubSidToken); err == nil || !strings.Contains(err.Error(), "missing both sub and sid") {
		t.Errorf("expected missing sub/sid error, got %v", err)
	}
}
