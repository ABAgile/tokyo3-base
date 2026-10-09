package api_test

import (
	"context"
	"io"
	"net/http"
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
