package oidcclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverEndpoints_UsesDocumentWhenPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"authorization_endpoint": "https://discovered.example/oauth2/v1/authorize",
			"token_endpoint": "https://discovered.example/oauth2/v1/token",
			"device_authorization_endpoint": "https://discovered.example/oauth2/v1/device"
		}`))
	}))
	defer srv.Close()

	ep := discoverEndpoints(context.Background(), srv.URL)
	if ep.AuthorizationEndpoint != "https://discovered.example/oauth2/v1/authorize" {
		t.Errorf("AuthorizationEndpoint = %q", ep.AuthorizationEndpoint)
	}
	if ep.TokenEndpoint != "https://discovered.example/oauth2/v1/token" {
		t.Errorf("TokenEndpoint = %q", ep.TokenEndpoint)
	}
	if ep.DeviceAuthorizationEndpoint != "https://discovered.example/oauth2/v1/device" {
		t.Errorf("DeviceAuthorizationEndpoint = %q", ep.DeviceAuthorizationEndpoint)
	}
}

func TestDiscoverEndpoints_FallsBackOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ep := discoverEndpoints(context.Background(), srv.URL)
	want := conventionEndpoints(srv.URL)
	if ep != want {
		t.Errorf("ep = %+v, want convention fallback %+v", ep, want)
	}
}

func TestDiscoverEndpoints_FallsBackOnMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	ep := discoverEndpoints(context.Background(), srv.URL)
	want := conventionEndpoints(srv.URL)
	if ep != want {
		t.Errorf("ep = %+v, want convention fallback %+v", ep, want)
	}
}

func TestDiscoverEndpoints_PartialDocumentFillsRemainingFromConvention(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Only authorization_endpoint is present; token_endpoint and
		// device_authorization_endpoint should fall back individually.
		_, _ = w.Write([]byte(`{"authorization_endpoint": "https://discovered.example/authorize"}`))
	}))
	defer srv.Close()

	ep := discoverEndpoints(context.Background(), srv.URL)
	if ep.AuthorizationEndpoint != "https://discovered.example/authorize" {
		t.Errorf("AuthorizationEndpoint = %q", ep.AuthorizationEndpoint)
	}
	convention := conventionEndpoints(srv.URL)
	if ep.TokenEndpoint != convention.TokenEndpoint {
		t.Errorf("TokenEndpoint = %q, want convention fallback %q", ep.TokenEndpoint, convention.TokenEndpoint)
	}
	if ep.DeviceAuthorizationEndpoint != convention.DeviceAuthorizationEndpoint {
		t.Errorf("DeviceAuthorizationEndpoint = %q, want convention fallback %q",
			ep.DeviceAuthorizationEndpoint, convention.DeviceAuthorizationEndpoint)
	}
}

func TestDiscoverEndpoints_FallsBackOnUnreachable(t *testing.T) {
	// Port 0 dialed directly never listens; using an address that
	// refuses connections is more deterministic than a closed server.
	ep := discoverEndpoints(context.Background(), "http://127.0.0.1:1")
	want := conventionEndpoints("http://127.0.0.1:1")
	if ep != want {
		t.Errorf("ep = %+v, want convention fallback %+v", ep, want)
	}
}
