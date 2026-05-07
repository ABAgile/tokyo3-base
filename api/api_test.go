package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTransport wraps a base RoundTripper and records whether it was called.
type testTransport struct {
	called bool
	base   http.RoundTripper
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.called = true
	return t.base.RoundTrip(req)
}

// ── ApiError ──────────────────────────────────────────────────────────────────

func TestApiError(t *testing.T) {
	testCases := []struct {
		name     string
		code     int
		expected string
	}{
		{"ok", 200, "api error: status 200"},
		{"not found", 404, "api error: status 404"},
		{"server error", 500, "api error: status 500"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, (&ApiError{StatusCode: tc.code}).Error())
		})
	}
}

// ── RestyClient.R ─────────────────────────────────────────────────────────────

func TestRestyClient_R(t *testing.T) {
	type body struct {
		Message string `json:"message"`
	}

	testCases := []struct {
		name           string
		statusCode     int
		responseBody   any
		wantErr        bool
		wantApiErrCode int
	}{
		{
			name:         "success decodes result",
			statusCode:   http.StatusOK,
			responseBody: body{Message: "ok"},
		},
		{
			name:           "4xx returns ApiError",
			statusCode:     http.StatusBadRequest,
			responseBody:   body{Message: "bad"},
			wantErr:        true,
			wantApiErrCode: http.StatusBadRequest,
		},
		{
			name:           "5xx returns ApiError",
			statusCode:     http.StatusInternalServerError,
			responseBody:   body{Message: "error"},
			wantErr:        true,
			wantApiErrCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				json.NewEncoder(w).Encode(tc.responseBody)
			}))
			defer srv.Close()

			rc := NewRestClient(srv.URL)
			var result body
			err := rc.R(context.Background(), http.MethodGet, "/", &result)

			if tc.wantErr {
				require.Error(t, err)
				var apiErr *ApiError
				require.ErrorAs(t, err, &apiErr)
				assert.Equal(t, tc.wantApiErrCode, apiErr.StatusCode)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "ok", result.Message)
			}
		})
	}
}

func TestRestyClient_R_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // close immediately to force connection refused

	rc := NewRestClient(url)
	var result struct{}
	err := rc.R(context.Background(), http.MethodGet, "/", &result)
	assert.Error(t, err)
}

// ── ClientOption ──────────────────────────────────────────────────────────────

func TestClientOption_WithBaseUrl(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	rc := NewRestClient("http://wrong.invalid", CO.WithBaseUrl(srv.URL))
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{})
	assert.True(t, called, "request should reach the overridden base URL")
}

func TestClientOption_WithTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL, CO.WithTimeout(5*time.Millisecond))
	err := rc.R(context.Background(), http.MethodGet, "/", &struct{}{})
	assert.Error(t, err, "request should fail due to timeout")
}

func TestClientOption_WithRetryCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL, CO.WithRetryCount(2))
	assert.NoError(t, rc.R(context.Background(), http.MethodGet, "/", &struct{}{}))
}

func TestClientOption_WithDebug(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	rc := NewRestClient(srv.URL, CO.WithDebug(false))
	assert.NoError(t, rc.R(context.Background(), http.MethodGet, "/", &struct{}{}))
}

func TestClientOption_WithHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Custom")
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL, CO.WithHeader("X-Custom", "sentinel"))
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{})
	assert.Equal(t, "sentinel", got)
}

func TestClientOption_WithHeaders(t *testing.T) {
	got := make(map[string]string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got["A"] = r.Header.Get("A")
		got["B"] = r.Header.Get("B")
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL, CO.WithHeaders(map[string]string{"A": "1", "B": "2"}))
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{})
	assert.Equal(t, "1", got["A"])
	assert.Equal(t, "2", got["B"])
}

func TestClientOption_WithAuthToken(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL, CO.WithAuthToken("my-token"))
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{})
	assert.Equal(t, "Bearer my-token", got)
}

func TestClientOption_WithBasicAuth(t *testing.T) {
	var gotUser, gotPass string
	var gotOk bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOk = r.BasicAuth()
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL, CO.WithBasicAuth("user", "pass"))
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{})
	assert.True(t, gotOk)
	assert.Equal(t, "user", gotUser)
	assert.Equal(t, "pass", gotPass)
}

func TestClientOption_WithTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	tr := &testTransport{base: http.DefaultTransport}
	rc := NewRestClient(srv.URL, CO.WithTransport(tr))
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{})
	assert.True(t, tr.called, "custom transport should be invoked")
}

// ── RequestOption ─────────────────────────────────────────────────────────────

func TestRequestOption_WithDebug(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	rc := NewRestClient(srv.URL)
	assert.NoError(t, rc.R(context.Background(), http.MethodGet, "/", &struct{}{}, RO.WithDebug(false)))
}

func TestRequestOption_WithPathParam(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL)
	_ = rc.R(context.Background(), http.MethodGet, "/orders/{id}", &struct{}{},
		RO.WithPathParam("id", "123"))
	assert.Equal(t, "/orders/123", gotPath)
}

func TestRequestOption_WithPathParams(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL)
	_ = rc.R(context.Background(), http.MethodGet, "/users/{uid}/orders/{oid}", &struct{}{},
		RO.WithPathParams(map[string]string{"uid": "u1", "oid": "o2"}))
	assert.Equal(t, "/users/u1/orders/o2", gotPath)
}

func TestRequestOption_WithQueryParam(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("foo")
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL)
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{}, RO.WithQueryParam("foo", "bar"))
	assert.Equal(t, "bar", got)
}

func TestRequestOption_WithQueryParams(t *testing.T) {
	got := make(map[string]string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got["a"] = r.URL.Query().Get("a")
		got["b"] = r.URL.Query().Get("b")
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL)
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{},
		RO.WithQueryParams(map[string]string{"a": "1", "b": "2"}))
	assert.Equal(t, "1", got["a"])
	assert.Equal(t, "2", got["b"])
}

func TestRequestOption_WithBody(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL)
	_ = rc.R(context.Background(), http.MethodPost, "/", &struct{}{},
		RO.WithBody(map[string]string{"key": "val"}))
	assert.Equal(t, "val", got["key"])
}

func TestRequestOption_WithHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Req")
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL)
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{}, RO.WithHeader("X-Req", "per-request"))
	assert.Equal(t, "per-request", got)
}

func TestRequestOption_WithHeaders(t *testing.T) {
	got := make(map[string]string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got["X"] = r.Header.Get("X")
		got["Y"] = r.Header.Get("Y")
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL)
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{},
		RO.WithHeaders(map[string]string{"X": "1", "Y": "2"}))
	assert.Equal(t, "1", got["X"])
	assert.Equal(t, "2", got["Y"])
}

func TestRequestOption_WithAuthToken(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL)
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{}, RO.WithAuthToken("req-token"))
	assert.Equal(t, "Bearer req-token", got)
}

func TestRequestOption_WithBasicAuth(t *testing.T) {
	var gotUser, gotPass string
	var gotOk bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOk = r.BasicAuth()
	}))
	defer srv.Close()

	rc := NewRestClient(srv.URL)
	_ = rc.R(context.Background(), http.MethodGet, "/", &struct{}{}, RO.WithBasicAuth("u", "p"))
	assert.True(t, gotOk)
	assert.Equal(t, "u", gotUser)
	assert.Equal(t, "p", gotPass)
}
