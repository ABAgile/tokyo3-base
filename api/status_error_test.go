package api_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/api"
	"github.com/go-resty/resty/v2"
)

// Only 2xx is success: a 3xx that was not followed must not be reported as a
// successful call. A 304 is covered by TestR_NotModifiedReturnsErrNotModified.
func TestR_NonSuccessStatusIsAPIError(t *testing.T) {
	// Returning http.ErrUseLastResponse hands back the 3xx unfollowed, with no error.
	noFollow := api.RestyClientOption(func(c *resty.Client) {
		c.SetRedirectPolicy(resty.RedirectPolicyFunc(func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}))
	})
	cases := []struct {
		name   string
		status int
		opts   []api.RestyClientOption
	}{
		{name: "300 multiple choices", status: http.StatusMultipleChoices},
		{name: "302 redirect not followed", status: http.StatusFound, opts: []api.RestyClientOption{noFollow}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			err := api.NewRestClient(srv.URL, tc.opts...).R(context.Background(), http.MethodGet, "/x", nil)
			var apiErr *api.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status {
				t.Fatalf("want APIError %d, got %T %v", tc.status, err, err)
			}
		})
	}
}

// A 304 answers a conditional request whose validator still matches. R
// reports it as ErrNotModified, which is not an APIError and not success.
func TestR_NotModifiedReturnsErrNotModified(t *testing.T) {
	const etag = `"v1"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = io.WriteString(w, `{"name":"fresh"}`)
	}))
	defer srv.Close()
	c := api.NewRestClient(srv.URL)

	if err := c.R(context.Background(), http.MethodGet, "/x", nil); err != nil {
		t.Fatalf("first request: %v", err)
	}
	err := c.R(context.Background(), http.MethodGet, "/x", nil, api.RO.WithHeader("If-None-Match", etag))
	if !errors.Is(err, api.ErrNotModified) {
		t.Fatalf("want ErrNotModified, got %T %v", err, err)
	}
	if _, ok := errors.AsType[*api.APIError](err); ok {
		t.Fatalf("304 must not be an APIError: %v", err)
	}
}

// The error-body cap also applies to non-2xx redirects, so an unfollowed
// redirect cannot buffer an unbounded body.
func TestR_RedirectErrorBodyIsCapped(t *testing.T) {
	const limit = 64 * 1024
	big := strings.Repeat("x", 2*limit)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMultipleChoices)
		_, _ = io.WriteString(w, big)
	}))
	defer srv.Close()

	err := api.NewRestClient(srv.URL).R(context.Background(), http.MethodGet, "/x", nil)
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want APIError, got %T %v", err, err)
	}
	if len(apiErr.Body) != limit {
		t.Fatalf("body length = %d, want the %d-byte cap", len(apiErr.Body), limit)
	}
}
