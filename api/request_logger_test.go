package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeHeaders(t *testing.T) {
	testCases := []struct {
		name     string
		input    map[string][]string
		expected map[string][]string
	}{
		{
			name:     "redacts Authorization",
			input:    map[string][]string{"Authorization": {"Bearer secret"}},
			expected: map[string][]string{"Authorization": {"***redacted***"}},
		},
		{
			name:     "redacts Cookie",
			input:    map[string][]string{"Cookie": {"session=abc"}},
			expected: map[string][]string{"Cookie": {"***redacted***"}},
		},
		{
			name:     "case insensitive redaction",
			input:    map[string][]string{"AUTHORIZATION": {"secret"}, "COOKIE": {"val"}},
			expected: map[string][]string{"AUTHORIZATION": {"***redacted***"}, "COOKIE": {"***redacted***"}},
		},
		{
			name:     "passes through safe headers unchanged",
			input:    map[string][]string{"Content-Type": {"application/json"}, "X-Request-Id": {"abc"}},
			expected: map[string][]string{"Content-Type": {"application/json"}, "X-Request-Id": {"abc"}},
		},
		{
			name: "mixed headers",
			input: map[string][]string{
				"Authorization": {"Bearer secret"},
				"Content-Type":  {"application/json"},
			},
			expected: map[string][]string{
				"Authorization": {"***redacted***"},
				"Content-Type":  {"application/json"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, SanitizeHeaders(tc.input))
		})
	}
}

func TestWithLogAttr(t *testing.T) {
	testCases := []struct {
		name     string
		attrs    [][2]string
		expected map[string]string
	}{
		{
			name:     "single attr",
			attrs:    [][2]string{{"key", "val"}},
			expected: map[string]string{"key": "val"},
		},
		{
			name:     "chained attrs accumulate",
			attrs:    [][2]string{{"a", "1"}, {"b", "2"}},
			expected: map[string]string{"a": "1", "b": "2"},
		},
		{
			name:     "later value overwrites earlier",
			attrs:    [][2]string{{"k", "first"}, {"k", "second"}},
			expected: map[string]string{"k": "second"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			for _, kv := range tc.attrs {
				ctx = WithLogAttr(ctx, kv[0], kv[1])
			}
			got, _ := ctx.Value(logAttrsKey).(map[string]string)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestWithLogAttrs(t *testing.T) {
	testCases := []struct {
		name     string
		seed     map[string]string
		add      map[string]string
		expected map[string]string
	}{
		{
			name:     "adds to empty context",
			add:      map[string]string{"a": "1", "b": "2"},
			expected: map[string]string{"a": "1", "b": "2"},
		},
		{
			name:     "merges with existing attrs",
			seed:     map[string]string{"a": "1"},
			add:      map[string]string{"b": "2"},
			expected: map[string]string{"a": "1", "b": "2"},
		},
		{
			name:     "add overwrites existing key",
			seed:     map[string]string{"a": "old"},
			add:      map[string]string{"a": "new"},
			expected: map[string]string{"a": "new"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.seed != nil {
				ctx = WithLogAttrs(ctx, tc.seed)
			}
			ctx = WithLogAttrs(ctx, tc.add)
			got, _ := ctx.Value(logAttrsKey).(map[string]string)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestWithLogAttr_DoesNotMutateParent(t *testing.T) {
	parent := WithLogAttr(context.Background(), "key", "val")
	_ = WithLogAttr(parent, "extra", "data")
	got, _ := parent.Value(logAttrsKey).(map[string]string)
	assert.NotContains(t, got, "extra", "parent context must not be mutated by child WithLogAttr")
}

func TestWithRequestLogger(t *testing.T) {
	type payload struct{ Status string }

	testCases := []struct {
		name        string
		method      string
		path        string
		ctxAttrs    map[string]string
		reqOpts     []RestyRequestOption
		logContains []string
	}{
		{
			name:        "logs outgoing request with method",
			logContains: []string{"OUTGOING_REQUEST", "GET"},
		},
		{
			name:        "logs incoming response with method and status",
			logContains: []string{"INCOMING_RESPONSE", "GET", "200"},
		},
		{
			name:        "context attrs appear in both log lines",
			ctxAttrs:    map[string]string{"plan_no": "P123", "tref": "T456"},
			logContains: []string{"plan_no: [P123]", "tref: [T456]"},
		},
		{
			name:        "logs request body",
			method:      http.MethodPost,
			reqOpts:     []RestyRequestOption{RO.WithBody(map[string]string{"bodymarker": "present"})},
			logContains: []string{"bodymarker"},
		},
		{
			name:        "logs query params in URL",
			reqOpts:     []RestyRequestOption{RO.WithQueryParam("page", "3")},
			logContains: []string{"page=3"},
		},
		{
			name:        "logs path params in URL",
			path:        "/items/{id}",
			reqOpts:     []RestyRequestOption{RO.WithPathParam("id", "42")},
			logContains: []string{"42"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(payload{Status: "ok"})
			}))
			defer srv.Close()

			method := http.MethodGet
			if tc.method != "" {
				method = tc.method
			}
			path := "/"
			if tc.path != "" {
				path = tc.path
			}

			var buf bytes.Buffer
			rc := NewRestClient(srv.URL, CO.WithRequestLogger(slog.New(slog.NewTextHandler(&buf, nil))))

			ctx := context.Background()
			if tc.ctxAttrs != nil {
				ctx = WithLogAttrs(ctx, tc.ctxAttrs)
			}

			var result payload
			require.NoError(t, rc.R(ctx, method, path, &result, tc.reqOpts...))

			for _, s := range tc.logContains {
				assert.Contains(t, buf.String(), s)
			}
		})
	}
}
