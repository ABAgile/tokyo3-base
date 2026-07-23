package oidcclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// discoveryTimeout bounds the discovery-document fetch. Short and
// separate from the per-request timeouts elsewhere in this package —
// a slow or hanging discovery endpoint should fail fast into the
// convention fallback, not stall the whole login/refresh attempt.
const discoveryTimeout = 10 * time.Second

// endpoints is the subset of the OIDC discovery document (OpenID
// Connect Discovery 1.0 / RFC 8414) this package needs to build
// authorize/device/token URLs for any standards-compliant IdP —
// required for interop with IdPs whose paths don't happen to match
// tokyo3-auth's fixed /authorize + /token + /device_authorization
// convention (e.g. Okta, Google, Auth0).
type endpoints struct {
	AuthorizationEndpoint       string
	TokenEndpoint               string
	DeviceAuthorizationEndpoint string
}

// conventionEndpoints returns the tokyo3-auth path convention this
// package used unconditionally before discovery support was added —
// the fallback when discovery is unavailable or incomplete, and the
// exact behavior [BuildAuthorizeURL] still documents.
func conventionEndpoints(issuer string) endpoints {
	base := strings.TrimRight(issuer, "/")
	return endpoints{
		AuthorizationEndpoint:       base + "/authorize",
		TokenEndpoint:               base + "/token",
		DeviceAuthorizationEndpoint: base + "/device_authorization",
	}
}

// discoverEndpoints fetches {issuer}/.well-known/openid-configuration and
// returns its authorize/token/device_authorization endpoints, falling
// back to [conventionEndpoints] wherever the document is unreachable,
// non-200, malformed, or missing a given field. Never returns an error:
// every caller in this package already tolerates the convention as a
// valid answer, so a discovery hiccup degrades to today's exact
// pre-discovery behavior rather than blocking login.
func discoverEndpoints(ctx context.Context, issuer string) endpoints {
	fallback := conventionEndpoints(issuer)

	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	url := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fallback
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fallback
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fallback
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fallback
	}
	var doc struct {
		AuthorizationEndpoint       string `json:"authorization_endpoint"`
		TokenEndpoint               string `json:"token_endpoint"`
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fallback
	}

	ep := fallback
	if doc.AuthorizationEndpoint != "" {
		ep.AuthorizationEndpoint = doc.AuthorizationEndpoint
	}
	if doc.TokenEndpoint != "" {
		ep.TokenEndpoint = doc.TokenEndpoint
	}
	if doc.DeviceAuthorizationEndpoint != "" {
		ep.DeviceAuthorizationEndpoint = doc.DeviceAuthorizationEndpoint
	}
	return ep
}
