package api_test

import (
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/api"
)

func TestR_TransportErrorRedactsCredentialQuery(t *testing.T) {
	c := api.NewRestClient("http://127.0.0.1:1")
	err := c.R(context.Background(), http.MethodGet, "/x", nil,
		api.RO.WithQueryParams(map[string]string{"key": "SECRETKEY", "address": "tokyo"}))
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if got := err.Error(); strings.Contains(got, "SECRETKEY") {
		t.Fatalf("error leaks the API key: %v", got)
	}
	if !strings.Contains(err.Error(), "address=tokyo") {
		t.Fatalf("non-sensitive params should survive: %v", err)
	}
}

func TestR_EmptyGzipErrorBodyStillReportsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusInternalServerError)
		w.(http.Flusher).Flush() // chunked, zero bytes
	}))
	defer srv.Close()

	err := api.NewRestClient(srv.URL).R(context.Background(), http.MethodGet, "/x", nil,
		api.RO.WithHeader("Accept-Encoding", "gzip"))
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("want APIError 500, got %T %v", err, err)
	}
}

func TestR_GzipErrorBodyStillDecoded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusBadRequest)
		zw := gzip.NewWriter(w)
		_, _ = zw.Write([]byte("bad input"))
		_ = zw.Close()
	}))
	defer srv.Close()

	err := api.NewRestClient(srv.URL).R(context.Background(), http.MethodGet, "/x", nil,
		api.RO.WithHeader("Accept-Encoding", "gzip"))
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || string(apiErr.Body) != "bad input" {
		t.Fatalf("want decoded body, got %T %v", err, err)
	}
}
