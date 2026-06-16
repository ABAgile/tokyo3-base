package httpauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abagile/tokyo3-base/httpauth"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // distinct from 200/401 so we can tell "served"
	})
}

func TestBasicAuth_DisabledPassesThrough(t *testing.T) {
	h := httpauth.BasicAuth(httpauth.BasicAuthConfig{}, okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secret", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("disabled gate should serve next; got %d", rec.Code)
	}
}

func TestBasicAuth_RejectsMissingAndWrong(t *testing.T) {
	h := httpauth.BasicAuth(httpauth.BasicAuthConfig{Username: "admin", Password: "s3cret", Realm: "test"}, okHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secret", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no creds: got %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="test", charset="UTF-8"` {
		t.Errorf("challenge header = %q", got)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	req.SetBasicAuth("admin", "wrong")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong pass: got %d, want 401", rec.Code)
	}
}

func TestBasicAuth_AcceptsCorrect(t *testing.T) {
	h := httpauth.BasicAuth(httpauth.BasicAuthConfig{Username: "admin", Password: "s3cret"}, okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	req.SetBasicAuth("admin", "s3cret")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("correct creds should serve next; got %d", rec.Code)
	}
}

func TestBasicAuth_ExemptPathBypasses(t *testing.T) {
	h := httpauth.BasicAuth(httpauth.BasicAuthConfig{Username: "admin", Password: "s3cret"}, okHandler(), "/healthz")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("exempt path should bypass gate; got %d", rec.Code)
	}
}
