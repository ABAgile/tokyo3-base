package oidcclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// deviceSleeper is the channel-based sleep used between device-flow
// poll attempts. Production defaults to time.After; tests swap it via
// the helper in export_test.go so the RFC 8628 polling loop runs in
// microseconds instead of the wire-mandated 1+s/cycle.
var deviceSleeper = func(d time.Duration) <-chan time.Time { return time.After(d) }

// RunDeviceFlow performs the RFC 8628 device authorization grant.
// Prints the verification URL + user code to stderr (or io.Discard if
// stderr is nil), then polls /token at the server-supplied interval
// — applying slow_down backoff — until the user approves on a second
// device or the grant expires.
//
// Required when the host running this CLI has no browser (CI runners,
// remote shells, container builds). The OAuth client must have
// allow_device_grant enabled at the issuer's admin surface.
func RunDeviceFlow(ctx context.Context, issuer, clientID string, stderr io.Writer) (*Tokens, error) {
	authzURL := strings.TrimRight(issuer, "/") + "/device_authorization"
	tokenURL := strings.TrimRight(issuer, "/") + "/token"

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", "openid email profile offline_access")
	authzCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(authzCtx, http.MethodPost, authzURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device_authorization: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device_authorization %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var authz struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &authz); err != nil {
		return nil, fmt.Errorf("decode device_authorization: %w", err)
	}
	if authz.Interval <= 0 {
		authz.Interval = 5
	}
	if authz.ExpiresIn <= 0 {
		authz.ExpiresIn = 900
	}

	if stderr != nil {
		fmt.Fprintln(stderr, "Visit this URL to approve sign-in:")
		if authz.VerificationURIComplete != "" {
			fmt.Fprintln(stderr, "  ", authz.VerificationURIComplete)
		} else {
			fmt.Fprintln(stderr, "  ", authz.VerificationURI)
		}
		fmt.Fprintln(stderr, "Or open this URL and enter the code below:")
		fmt.Fprintln(stderr, "  ", authz.VerificationURI)
		fmt.Fprintln(stderr, "  code:", authz.UserCode)
		fmt.Fprintln(stderr, "Waiting for approval…")
	}

	deadline := time.Now().Add(time.Duration(authz.ExpiresIn) * time.Second)
	interval := time.Duration(authz.Interval) * time.Second
	for {
		if time.Now().After(deadline) {
			return nil, errors.New("device code expired before approval")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deviceSleeper(interval):
		}
		pollForm := url.Values{}
		pollForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		pollForm.Set("device_code", authz.DeviceCode)
		pollForm.Set("client_id", clientID)

		pollCtx, pollCancel := context.WithTimeout(ctx, 15*time.Second)
		pollReq, err := http.NewRequestWithContext(pollCtx, http.MethodPost, tokenURL,
			strings.NewReader(pollForm.Encode()))
		if err != nil {
			pollCancel()
			return nil, err
		}
		pollReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		pollReq.Header.Set("Accept", "application/json")
		pollResp, err := http.DefaultClient.Do(pollReq)
		pollCancel()
		if err != nil {
			return nil, fmt.Errorf("token poll: %w", err)
		}
		pollBody, _ := io.ReadAll(io.LimitReader(pollResp.Body, 64*1024))
		pollResp.Body.Close()

		if pollResp.StatusCode == http.StatusOK {
			var raw struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
				IDToken      string `json:"id_token"`
				ExpiresIn    int64  `json:"expires_in"`
			}
			if err := json.Unmarshal(pollBody, &raw); err != nil {
				return nil, fmt.Errorf("decode token response: %w", err)
			}
			if raw.AccessToken == "" {
				return nil, errors.New("token endpoint returned no access_token")
			}
			return &Tokens{
				AccessToken:  raw.AccessToken,
				RefreshToken: raw.RefreshToken,
				IDToken:      raw.IDToken,
				Expiration:   time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second),
			}, nil
		}
		// Non-200: decode the RFC 8628 error code so we can distinguish
		// "keep polling" from "abort." Anything we don't recognise is
		// treated as terminal.
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(pollBody, &errResp)
		switch errResp.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += time.Duration(authz.Interval) * time.Second
			continue
		case "access_denied":
			return nil, errors.New("authorization denied by user")
		case "expired_token":
			return nil, errors.New("device code expired before approval")
		default:
			return nil, fmt.Errorf("token poll: %s %s",
				errResp.Error, strings.TrimSpace(errResp.ErrorDescription))
		}
	}
}
