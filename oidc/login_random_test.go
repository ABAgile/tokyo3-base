package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abagile/tokyo3-base/internal/randtest"
)

// Begin draws the state, nonce, and PKCE verifier before it touches the cookie.
// If that draw fails, the login must not start: no authorize URL, and no flow
// cookie that would let a callback match a partial flow.
func TestBegin_FailsWithoutFlowWhenEntropyFails(t *testing.T) {
	a := testAuth(t, stubTok{}, nil)
	rec := httptest.NewRecorder()
	var authURL string
	var err error
	randtest.FailAfter(t, 0, func() {
		authURL, err = a.Begin(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil), "")
	})
	// Exact message: a later draw (the flow cookie's nonce) fails too, and its
	// error also mentions entropy. Only this message shows the first draw failed.
	if err == nil || err.Error() != "oidc: generate flow entropy" {
		t.Fatalf("err = %v, want the flow-entropy error from the first draw", err)
	}
	if authURL != "" {
		t.Errorf("Begin returned an authorize URL alongside the error")
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == a.flow.Name {
			t.Errorf("flow cookie %q set despite the failed draw", c.Name)
		}
	}
}
