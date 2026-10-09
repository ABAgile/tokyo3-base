package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// oversizedErrorServer answers 500 with a body twice the retained-body limit.
func oversizedErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 2*apiErrorBodyLimit))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The error-body wrapper with no base transport must use the default transport,
// and still bound what it hands back.
func TestErrorBodyTransport_NilBaseUsesDefaultAndBoundsBody(t *testing.T) {
	srv := oversizedErrorServer(t)
	client := &http.Client{Transport: errorBodyTransport{}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 passed through", resp.StatusCode)
	}
	var got bytes.Buffer
	if _, err := got.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	if got.Len() > apiErrorBodyLimit {
		t.Errorf("error body = %d bytes, want at most %d", got.Len(), apiErrorBodyLimit)
	}
}

// A caller that replaces the transport after construction drops the wrapper.
// The API layer must still cap the error body it keeps.
func TestRestyClient_ReplacedTransportStillCapsErrorBody(t *testing.T) {
	srv := oversizedErrorServer(t)
	rc := NewRestClient(srv.URL)
	rc.GetClient().Transport = http.DefaultTransport

	err := rc.R(context.Background(), http.MethodGet, "/", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want an *APIError", err)
	}
	if len(apiErr.Body) != apiErrorBodyLimit {
		t.Errorf("retained %d body bytes, want %d", len(apiErr.Body), apiErrorBodyLimit)
	}
}

// An error response labelled gzip whose body is not gzip keeps its status and
// passes its bytes through undecoded, so an HTTP error still reaches callers as
// an error status rather than a transport failure. The request asks for gzip
// itself, so the transport leaves the body encoded and the wrapper tries to
// decode it.
func TestErrorBodyTransport_InvalidGzipErrorBodyKeepsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("definitely not gzip"))
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	client := &http.Client{Transport: errorBodyTransport{}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("undecodable gzip error body failed the request: %v", err)
	}
	defer resp.Body.Close()
	body := new(strings.Builder)
	_, _ = io.Copy(body, resp.Body)
	if resp.StatusCode != http.StatusInternalServerError || body.String() != "definitely not gzip" || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("status=%d body=%q encoding=%q", resp.StatusCode, body.String(), resp.Header.Get("Content-Encoding"))
	}
}

// Closing idle connections on a wrapper with no base transport must be safe.
func TestErrorBodyTransport_CloseIdleConnectionsWithoutBase(t *testing.T) {
	errorBodyTransport{}.CloseIdleConnections()
}

// A success response that is not JSON is a decode error, not an empty result.
func TestRestyClient_UndecodableSuccessBodyFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>not json</html>"))
	}))
	defer srv.Close()

	var out struct{ Status string }
	err := NewRestClient(srv.URL).R(context.Background(), http.MethodGet, "/", &out)
	if err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("err = %v, want a decode error", err)
	}
}

// With no refresher configured, a token that is close to expiry but still valid
// is returned rather than failing the call.
func TestBearerTokenManager_NilRefresherKeepsUsableToken(t *testing.T) {
	tm := &BearerTokenManager{Token: "still-valid", ExpiresAt: time.Now().Add(time.Minute)}
	got, err := tm.GetToken(context.Background())
	if err != nil || got != "still-valid" {
		t.Fatalf("GetToken = %q, %v; want the usable token", got, err)
	}
}
