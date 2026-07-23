package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeLogoutVerifier is a controllable LogoutTokenVerifier stub.
type fakeLogoutVerifier struct {
	claims *LogoutClaims
	err    error
}

func (f *fakeLogoutVerifier) VerifyLogoutToken(context.Context, string) (*LogoutClaims, error) {
	return f.claims, f.err
}

// fakeRevoker is a controllable LogoutRevoker stub recording calls for
// assertions.
type fakeRevoker struct {
	sessionRevoked    int64
	sessionErr        error
	gotSID            string
	userRevoked       int64
	userIdentity      string
	userOK            bool
	userErr           error
	gotIssuer, gotSub string
}

func (f *fakeRevoker) RevokeSession(_ context.Context, sid string) (int64, error) {
	f.gotSID = sid
	return f.sessionRevoked, f.sessionErr
}

func (f *fakeRevoker) RevokeUser(_ context.Context, issuer, subject string) (int64, string, bool, error) {
	f.gotIssuer, f.gotSub = issuer, subject
	return f.userRevoked, f.userIdentity, f.userOK, f.userErr
}

func postLogout(h http.Handler, token string) *httptest.ResponseRecorder {
	form := url.Values{}
	if token != "" {
		form.Set("logout_token", token)
	}
	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNewBackchannelLogoutHandler_RequiresVerifierAndRevoker(t *testing.T) {
	ver := &fakeLogoutVerifier{}
	rev := &fakeRevoker{}
	if _, err := NewBackchannelLogoutHandler(BackchannelLogoutConfig{Revoker: rev}); err == nil {
		t.Error("want error when Verifier is nil")
	}
	if _, err := NewBackchannelLogoutHandler(BackchannelLogoutConfig{Verifier: ver}); err == nil {
		t.Error("want error when Revoker is nil")
	}
	if _, err := NewBackchannelLogoutHandler(BackchannelLogoutConfig{Verifier: ver, Revoker: rev}); err != nil {
		t.Errorf("want no error with both set, got %v", err)
	}
}

func TestBackchannelLogoutHandler_MissingToken(t *testing.T) {
	h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{
		Verifier: &fakeLogoutVerifier{}, Revoker: &fakeRevoker{},
	})
	rec := postLogout(h, "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestBackchannelLogoutHandler_InvalidToken(t *testing.T) {
	h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{
		Verifier: &fakeLogoutVerifier{err: errors.New("bad signature")},
		Revoker:  &fakeRevoker{},
	})
	rec := postLogout(h, "garbage")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestBackchannelLogoutHandler_SessionScoped(t *testing.T) {
	rev := &fakeRevoker{sessionRevoked: 2}
	h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{
		Verifier: &fakeLogoutVerifier{claims: &LogoutClaims{SessionID: "sid-1", JTI: "jti-1"}},
		Revoker:  rev,
	})
	rec := postLogout(h, "signed-jwt")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	if rev.gotSID != "sid-1" {
		t.Errorf("RevokeSession called with %q, want sid-1", rev.gotSID)
	}
}

func TestBackchannelLogoutHandler_UserFallback(t *testing.T) {
	rev := &fakeRevoker{userRevoked: 1, userIdentity: "alice@example.com", userOK: true}
	h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{
		Verifier: &fakeLogoutVerifier{claims: &LogoutClaims{Issuer: "https://idp.example", Subject: "sub-1", JTI: "jti-2"}},
		Revoker:  rev,
	})
	var gotScope, gotIdentity string
	var gotRevoked int64
	h.cfg.OnRevoked = func(_ *http.Request, _ *LogoutClaims, scope, identity string, revoked int64) error {
		gotScope, gotIdentity, gotRevoked = scope, identity, revoked
		return nil
	}
	rec := postLogout(h, "signed-jwt")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	if rev.gotIssuer != "https://idp.example" || rev.gotSub != "sub-1" {
		t.Errorf("RevokeUser called with issuer=%q sub=%q", rev.gotIssuer, rev.gotSub)
	}
	if gotScope != "user" || gotIdentity != "alice@example.com" || gotRevoked != 1 {
		t.Errorf("OnRevoked got scope=%q identity=%q revoked=%d", gotScope, gotIdentity, gotRevoked)
	}
}

func TestBackchannelLogoutHandler_UnknownUserIsIdempotentSuccess(t *testing.T) {
	rev := &fakeRevoker{userOK: false}
	h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{
		Verifier: &fakeLogoutVerifier{claims: &LogoutClaims{Subject: "unknown-sub", JTI: "jti-3"}},
		Revoker:  rev,
	})
	called := false
	h.cfg.OnRevoked = func(_ *http.Request, _ *LogoutClaims, scope, identity string, revoked int64) error {
		called = true
		if scope != "user" || identity != "" || revoked != 0 {
			t.Errorf("OnRevoked got scope=%q identity=%q revoked=%d, want user/\"\"/0", scope, identity, revoked)
		}
		return nil
	}
	rec := postLogout(h, "signed-jwt")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q, want 200 (unknown user is idempotent success)", rec.Code, rec.Body.String())
	}
	if !called {
		t.Error("OnRevoked was not called for the unknown-user path")
	}
}

func TestBackchannelLogoutHandler_RejectsReplay(t *testing.T) {
	h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{
		Verifier: &fakeLogoutVerifier{claims: &LogoutClaims{SessionID: "sid-1", JTI: "jti-dup"}},
		Revoker:  &fakeRevoker{},
	})
	first := postLogout(h, "signed-jwt")
	if first.Code != http.StatusOK {
		t.Fatalf("first call status = %d, want 200", first.Code)
	}
	second := postLogout(h, "signed-jwt")
	if second.Code != http.StatusBadRequest {
		t.Fatalf("replayed call status = %d, want 400", second.Code)
	}
}

func TestBackchannelLogoutHandler_RevokeSessionError(t *testing.T) {
	h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{
		Verifier: &fakeLogoutVerifier{claims: &LogoutClaims{SessionID: "sid-1", JTI: "jti-4"}},
		Revoker:  &fakeRevoker{sessionErr: errors.New("db down")},
	})
	rec := postLogout(h, "signed-jwt")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestBackchannelLogoutHandler_RevokeUserError(t *testing.T) {
	h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{
		Verifier: &fakeLogoutVerifier{claims: &LogoutClaims{Subject: "sub-1", JTI: "jti-5"}},
		Revoker:  &fakeRevoker{userErr: errors.New("db down")},
	})
	rec := postLogout(h, "signed-jwt")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestBackchannelLogoutHandler_OnRevokedErrorRenders500(t *testing.T) {
	h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{
		Verifier: &fakeLogoutVerifier{claims: &LogoutClaims{SessionID: "sid-1", JTI: "jti-6"}},
		Revoker:  &fakeRevoker{sessionRevoked: 1},
	})
	h.cfg.OnRevoked = func(*http.Request, *LogoutClaims, string, string, int64) error {
		return errors.New("audit unavailable")
	}
	rec := postLogout(h, "signed-jwt")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when OnRevoked fails", rec.Code)
	}
}

func TestBackchannelLogoutHandler_AlwaysSetsCacheControlNoStore(t *testing.T) {
	h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{
		Verifier: &fakeLogoutVerifier{claims: &LogoutClaims{SessionID: "sid-1", JTI: "jti-7"}},
		Revoker:  &fakeRevoker{},
	})
	rec := postLogout(h, "signed-jwt")
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}
