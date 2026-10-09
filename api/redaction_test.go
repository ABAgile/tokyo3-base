package api_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/api"
)

func TestR_TransportErrorRedactsPathParam(t *testing.T) {
	c := api.NewRestClient("http://127.0.0.1:1")
	err := c.R(context.Background(), http.MethodGet, "/reset/{token}", nil,
		api.RO.WithPathParam("token", "PATHSECRET"))
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if got := err.Error(); strings.Contains(got, "PATHSECRET") {
		t.Fatalf("error leaks the path token: %v", got)
	}
}

// TestR_RetryLogRedactsCredentials runs against stderr, because Resty writes
// its retry log there. It must not run in parallel.
func TestR_RetryLogRedactsCredentials(t *testing.T) {
	var err error
	logs := captureStderr(t, func() {
		c := api.NewRestClient("http://127.0.0.1:1", api.CO.WithRetryCount(1))
		err = c.R(context.Background(), http.MethodGet, "/reset/{token}", nil,
			api.RO.WithQueryParams(map[string]string{"api_key": "SECRETKEY"}),
			api.RO.WithPathParam("token", "PATHSECRET"))
	})
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if !strings.Contains(logs, "RESTY") {
		t.Fatalf("expected Resty to log the failed attempts, got %q", logs)
	}
	for _, secret := range []string{"SECRETKEY", "PATHSECRET"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("retry log leaks %s: %s", secret, logs)
		}
	}
}

// captureStderr returns what fn writes to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	func() {
		defer func() { os.Stderr = orig }()
		fn()
	}()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// Path params set on the client, and raw path params, are substituted into the
// URL like request-scoped ones, so they must be redacted the same way.
func TestRequestLogger_RedactsClientAndRawPathParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	setups := map[string]func(*api.RestyClient){
		"client path param": func(rc *api.RestyClient) { rc.SetPathParam("access_token", "CLIENTSECRET") },
		"client raw param":  func(rc *api.RestyClient) { rc.SetRawPathParam("access_token", "CLIENTSECRET") },
	}
	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			rc := api.NewRestClient(srv.URL, api.CO.WithRequestLogger(slog.New(slog.NewTextHandler(&buf, nil))))
			setup(rc)
			if err := rc.R(context.Background(), http.MethodGet, "/reset/{access_token}", nil); err != nil {
				t.Fatal(err)
			}
			logs := buf.String()
			if !strings.Contains(logs, "OUTGOING_REQUEST") || !strings.Contains(logs, "INCOMING_RESPONSE") {
				t.Fatalf("expected request and response logs, got %q", logs)
			}
			if strings.Contains(logs, "CLIENTSECRET") {
				t.Fatalf("request logs leak the client path param: %s", logs)
			}
		})
	}
}

// A client-level path param must also be redacted from transport errors and
// Resty's retry log, which embed the request URL.
func TestR_ClientPathParamRedactedInErrorAndRetryLog(t *testing.T) {
	var err error
	logs := captureStderr(t, func() {
		c := api.NewRestClient("http://127.0.0.1:1", api.CO.WithRetryCount(1))
		c.SetPathParam("token", "CLIENTSECRET")
		err = c.R(context.Background(), http.MethodGet, "/reset/{token}", nil)
	})
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if strings.Contains(err.Error(), "CLIENTSECRET") {
		t.Fatalf("error leaks the client path param: %v", err)
	}
	if strings.Contains(logs, "CLIENTSECRET") {
		t.Fatalf("retry log leaks the client path param: %s", logs)
	}
}
