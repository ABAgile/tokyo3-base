package session

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/csrf"
)

// IsExempt is the public counterpart of the Gate's exempt set. A caller
// composing its own route uses it to confirm that route bypasses the Gate.
func TestIsExempt_LoginLogoutAndConfiguredPaths(t *testing.T) {
	m := testManager(t, func(c *Config) { c.ExemptPaths = []string{"/healthz"} })
	for _, p := range []string{"/auth/login", "/auth/logout", "/healthz"} {
		if !m.IsExempt(p) {
			t.Errorf("IsExempt(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/roles", "/auth/login/extra", ""} {
		if m.IsExempt(p) {
			t.Errorf("IsExempt(%q) = true, want false", p)
		}
	}
}

func TestValidateCSRF_RejectsRequestWithoutSession(t *testing.T) {
	m := testManager(t, nil)
	secret, err := m.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	token, err := csrf.Token(secret.CSRFSecret, "form")
	if err != nil {
		t.Fatal(err)
	}

	// No cookie at all: even a token minted for a real secret must fail.
	if m.ValidateCSRF(httptest.NewRequest(http.MethodPost, "/x", nil), token, "form") {
		t.Error("ValidateCSRF accepted a request with no session")
	}

	// Session cookie that does not open (tampered): same answer.
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: "not-a-sealed-value"})
	if m.ValidateCSRF(r, token, "form") {
		t.Error("ValidateCSRF accepted a request with a tampered session cookie")
	}

	// Control: the same token is accepted with the real session.
	sess := Session{Subject: "u", CSRFSecret: secret.CSRFSecret, Expiry: m.cfg.Now().Add(time.Hour)}
	r = httptest.NewRequest(http.MethodPost, "/x", nil)
	r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, sess)})
	if !m.ValidateCSRF(r, token, "form") {
		t.Error("ValidateCSRF rejected a valid token for a live session")
	}
}

// A session already at its absolute ceiling has nothing left to extend. The
// clamped extension equals the current expiry, so the cookie must not be
// re-sealed.
func TestGate_IdleExtend_NoReSealWhenAbsoluteCapReached(t *testing.T) {
	clk := newClock()
	m := testManager(t, func(c *Config) {
		c.IdleTimeout = 20 * time.Minute
		c.Now = clk.now
	})
	sess := Session{
		Subject:        "u",
		Expiry:         clk.now().Add(5 * time.Minute), // inside the half-window threshold
		AbsoluteExpiry: clk.now().Add(5 * time.Minute), // and already at the cap
	}
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, sess)})
	rec := httptest.NewRecorder()
	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("code = %d, want the request to proceed", rec.Code)
	}
	if n := len(rec.Result().Cookies()); n != 0 {
		t.Errorf("cookie re-sealed at the absolute cap (%d Set-Cookie headers)", n)
	}
}

// When the extended session no longer fits in a cookie, the re-seal fails.
// The request must still proceed on the existing cookie, and the failure must
// be logged rather than surfaced to the user.
func TestGate_IdleExtend_ReSealFailureKeepsRequestAlive(t *testing.T) {
	clk := newClock()
	logs := &bytes.Buffer{}
	m := testManager(t, func(c *Config) {
		c.IdleTimeout = 20 * time.Minute
		c.Now = clk.now
		c.Log = slog.New(slog.NewTextHandler(logs, nil))
	})
	groups := make([]string, 400) // sealed well past the ~4 KB cookie limit
	for i := range groups {
		groups[i] = fmt.Sprintf("group-%04d", i)
	}
	sess := Session{Subject: "u", Groups: groups, Expiry: clk.now().Add(5 * time.Minute)}
	r := httptest.NewRequest(http.MethodGet, "/roles", nil)
	r.AddCookie(&http.Cookie{Name: m.cookie.Name, Value: sessionCookieValue(t, m, sess)})
	rec := httptest.NewRecorder()
	h := m.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("code = %d, want the request to proceed despite the failed re-seal", rec.Code)
	}
	if n := len(rec.Result().Cookies()); n != 0 {
		t.Errorf("a failed re-seal still wrote %d cookie(s)", n)
	}
	if !strings.Contains(logs.String(), "re-seal failed") {
		t.Errorf("failed re-seal not logged: %q", logs.String())
	}
}
