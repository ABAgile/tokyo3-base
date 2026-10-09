package api

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// URLs reach the log through sanitizeURL, so credentials must not survive in
// any position: userinfo, sensitive query values, or a query that cannot be
// parsed at all.
func TestSanitizeURL(t *testing.T) {
	cases := []struct {
		name           string
		in             string
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:           "userinfo password is redacted and routing survives",
			in:             "https://alice:hunter2@api.example/x?y=1",
			mustContain:    []string{"api.example/x", "y=1"},
			mustNotContain: []string{"hunter2", "alice"},
		},
		{
			name:           "userinfo without password is redacted",
			in:             "https://alice@api.example/x",
			mustContain:    []string{"api.example/x"},
			mustNotContain: []string{"alice"},
		},
		{
			name:           "sensitive query value is redacted and its key kept",
			in:             "https://api.example/x?token=abc&page=2",
			mustContain:    []string{"token=", "page=2"},
			mustNotContain: []string{"abc"},
		},
		{
			// An unparseable query may hide a credential, so the whole query
			// is dropped rather than logged as-is.
			name:           "unparseable query is dropped entirely",
			in:             "https://api.example/x?%zz=1&token=abc",
			mustContain:    []string{"api.example/x"},
			mustNotContain: []string{"abc", "token", "%zz"},
		},
		{
			name:        "unparseable URL is replaced with a placeholder",
			in:          "http://[::1",
			mustContain: []string{"[invalid URL]"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeURL(tc.in)
			for _, s := range tc.mustContain {
				if !strings.Contains(got, s) {
					t.Errorf("sanitizeURL(%q) = %q, missing %q", tc.in, got, s)
				}
			}
			for _, s := range tc.mustNotContain {
				if strings.Contains(got, s) {
					t.Errorf("sanitizeURL(%q) = %q, leaked %q", tc.in, got, s)
				}
			}
		})
	}
}

// A path that already carries a query must get the extra query parameters
// appended with "&", not a second "?".
func TestWithRequestLogger_AppendsParamsToExistingQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status":"ok"}`))
	}))
	defer srv.Close()

	var buf bytes.Buffer
	rc := NewRestClient(srv.URL, CO.WithRequestLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	var result struct{ Status string }
	if err := rc.R(context.Background(), http.MethodGet, "/items?a=1", &result, RO.WithQueryParams(map[string]string{"page": "3"})); err != nil {
		t.Fatal(err)
	}
	// Check the OUTGOING line specifically: the INCOMING line logs resty's own
	// request URL, which is already correct and would hide a bad join here.
	for line := range strings.SplitSeq(buf.String(), "\n") {
		if strings.Contains(line, "OUTGOING_REQUEST") {
			if !strings.Contains(line, "a=1&page=3") {
				t.Errorf("outgoing log does not join the query with '&': %s", line)
			}
			return
		}
	}
	t.Errorf("no OUTGOING_REQUEST line logged:\n%s", buf.String())
}

// A nil logger falls back to slog.Default(), so requests are still logged
// rather than panicking or silently dropping the lines.
func TestWithRequestLogger_NilLoggerUsesDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status":"ok"}`))
	}))
	defer srv.Close()

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rc := NewRestClient(srv.URL, CO.WithRequestLogger(nil))
	var result struct{ Status string }
	if err := rc.R(context.Background(), http.MethodGet, "/", &result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "OUTGOING_REQUEST") {
		t.Errorf("nil logger did not fall back to slog.Default:\n%s", buf.String())
	}
}
