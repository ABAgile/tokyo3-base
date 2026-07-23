// Package oidcclient is the OIDC public-client helper shared by SSO
// CLI tools that need an OIDC bearer token. It owns the OAuth 2.0
// authorization-code-with-PKCE flow, the RFC 8628 device authorization
// grant, refresh-token rotation, and on-disk persistence of the
// resulting Tokens under $XDG_CONFIG_HOME/auth-sso/.
//
// Sits under the auth/ namespace alongside other auth primitives
// (auth/creds for password + token hashing, auth/awsclaims for the
// AWS STS federation claim shape, auth/jwt for RS256 signing).
// Infrastructure packages (db/, journal/, nats/, tls/) stay at the
// top level.
//
// SSO state (config.json + tokens.json) is shared across every helper
// that uses this package — a single `login` populates the cache for
// all of them. Helper-specific outputs (downstream tokens, generated
// keys, role-mapped credentials, whatever the helper persists) live
// in per-helper subdirectories under the same root, accessed via
// AppCacheDir(name).
//
// Cache layout:
//
//	~/.config/auth-sso/
//	├── config.json          shared SSO state (issuer + client_id)
//	├── tokens.json          shared OAuth access + refresh + id_token
//	└── <helper>/            per-helper outputs (any files the helper persists)
//
// <helper> is whatever appName the consuming binary passes to
// AppCacheDir. Convention: strip any "auth-" prefix from the binary
// name, so a binary called auth-foo-creds writes to ~/.config/auth-sso/foo-creds/.
//
// Dependencies are deliberately limited to the Go standard library so
// every consumer stays statically linkable, fast to install, and free
// of OAuth library version drift.
package oidcclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// rootDirName is the single top-level directory under
// $XDG_CONFIG_HOME that holds all SSO state. Hardcoded rather than
// per-helper so a single `login` serves every helper in the
// installation.
const rootDirName = "auth-sso"

// Config is the non-secret configuration persisted at
// $XDG_CONFIG_HOME/auth-sso/config.json. The issuer + client_id are
// captured at login time so subsequent `get` invocations don't need
// flags.
type Config struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
}

// Tokens is the OAuth2 + OIDC response, with Expiration normalized to
// an absolute timestamp at parse time. IDToken is empty when the
// issuer didn't return one (e.g., scope=openid was omitted, or the
// refresh response decided not to re-issue it — EnsureFreshTokens
// preserves the previously-cached value in that case).
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token,omitempty"`
	Expiration   time.Time `json:"expiration"`
}

// CacheDir returns $XDG_CONFIG_HOME/auth-sso/, creating it with mode
// 0o700 if missing. Shared across every helper using this package —
// the SSO state (config + tokens) lives at the root, helper-specific
// outputs go in subdirs via AppCacheDir.
func CacheDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, rootDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// AppCacheDir returns $XDG_CONFIG_HOME/auth-sso/<appName>/, creating
// it with mode 0o700 if missing. Each helper roots its own outputs
// (per-resource sub-caches, generated keys, downstream configs, etc.)
// under its appName subdir. Convention: pass the binary name minus
// any "auth-" prefix, so a binary called auth-foo-creds calls
// AppCacheDir("foo-creds").
//
// appName must match [A-Za-z0-9_-]+. The whitelist is deliberately
// strict: any caller-controlled input would still need to escape this
// to reach a path outside the SSO cache.
func AppCacheDir(appName string) (string, error) {
	if !validAppName(appName) {
		return "", fmt.Errorf("oidcclient: invalid appName %q (must match [A-Za-z0-9_-]+)", appName)
	}
	base, err := CacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, appName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// validAppName returns true when s matches [A-Za-z0-9_-]+. Excludes
// '.' to prevent ".." traversal and any string that resolves to the
// parent directory.
func validAppName(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z',
			'A' <= c && c <= 'Z',
			'0' <= c && c <= '9',
			c == '-' || c == '_':
			// allowed
		default:
			return false
		}
	}
	return true
}

// SaveConfig writes Config to disk atomically with mode 0o600.
func SaveConfig(c Config) error {
	dir, err := CacheDir()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(dir, "config.json"), b, 0o600)
}

// LoadConfig reads the persisted Config. Returns a descriptive error
// when the file is missing or the issuer/client_id are missing —
// callers can use this to nudge the user toward `<tool> login` before
// doing anything else.
func LoadConfig() (*Config, error) {
	dir, err := CacheDir()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Issuer == "" || c.ClientID == "" {
		return nil, errors.New("config.json incomplete (missing issuer or client_id)")
	}
	return &c, nil
}

// SaveTokens persists Tokens atomically with mode 0o600.
func SaveTokens(t *Tokens) error {
	dir, err := CacheDir()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(dir, "tokens.json"), b, 0o600)
}

// LoadTokens reads the cached Tokens file. Returns a descriptive
// error when the file does not exist so callers can suggest a login.
func LoadTokens() (*Tokens, error) {
	dir, err := CacheDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "tokens.json")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no SSO cache at %s; run login to authenticate", path)
	}
	if err != nil {
		return nil, err
	}
	var t Tokens
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// EnsureFreshTokens returns cached tokens, refreshing them in place if
// the access token is within accessSkew of expiry. The rotated
// refresh token (when present in the response) is persisted before
// returning so a crash mid-call doesn't leave the on-disk refresh
// token burnt.
//
// If the issuer doesn't re-issue an id_token on refresh, the
// previously-cached IDToken is retained — refresh responses are
// allowed to omit it per OIDC spec.
func EnsureFreshTokens(ctx context.Context, cfg Config, accessSkew time.Duration) (*Tokens, error) {
	tokens, err := LoadTokens()
	if err != nil {
		return nil, err
	}
	if time.Until(tokens.Expiration) >= accessSkew {
		return tokens, nil
	}
	fresh, err := Refresh(ctx, cfg.Issuer, cfg.ClientID, tokens.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token failed: %w (run login again)", err)
	}
	// Auth's /token may omit refresh_token if rotation is disabled.
	if fresh.RefreshToken == "" {
		fresh.RefreshToken = tokens.RefreshToken
	}
	// Refresh responses may omit id_token; keep the cached value.
	if fresh.IDToken == "" {
		fresh.IDToken = tokens.IDToken
	}
	if err := SaveTokens(fresh); err != nil {
		return nil, fmt.Errorf("save tokens: %w", err)
	}
	return fresh, nil
}

// Refresh swaps a refresh_token for a fresh access + (rotated)
// refresh + id_token triple. Callers must persist the new
// refresh_token before issuing any other call — auth rotates the
// refresh token on each use and the previous value is invalidated
// server-side.
func Refresh(ctx context.Context, issuer, clientID, refreshToken string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("refresh_token", refreshToken)
	return PostToken(ctx, issuer, form)
}

// PostToken POSTs to {issuer}/token and decodes the standard OAuth2
// response into a Tokens. expires_in is normalized into an absolute
// Expiration here so callers don't have to track the relative-vs-
// absolute time semantics. Exported because the device flow uses it
// for the polling exchange.
//
// PostToken assumes the {issuer}/token convention; use [PostTokenAt] when
// the token endpoint URL is already known (e.g. resolved via OIDC
// discovery) and may not follow that convention.
func PostToken(ctx context.Context, issuer string, form url.Values) (*Tokens, error) {
	return PostTokenAt(ctx, strings.TrimRight(issuer, "/")+"/token", form)
}

// PostTokenAt POSTs to the explicit tokenURL and decodes the standard
// OAuth2 response into a Tokens, exactly like [PostToken] but without
// assuming the {issuer}/token convention — for callers (e.g. a login
// broker driving a third-party IdP) that resolve the token endpoint via
// OIDC discovery instead.
func PostTokenAt(ctx context.Context, tokenURL string, form url.Values) (*Tokens, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
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

// IDTokenClaims extracts the JWT payload of an ID token without
// verifying the signature — the resource server (e.g., certd)
// re-verifies on receipt; this is purely for client-side conveniences
// like deriving a default key_id from the email/sub. Returns an empty
// struct (no error) when the token isn't a structurally valid JWS.
func IDTokenClaims(idToken string) IDTokenSubjectClaims {
	var out IDTokenSubjectClaims
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return out
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some issuers emit standard-base64 (with padding) instead of
		// raw — try that as a fallback before giving up.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return out
		}
	}
	_ = json.Unmarshal(payload, &out)
	return out
}

// IDTokenSubjectClaims is the subset of standard OIDC claims the
// client side needs locally. Servers re-verify the full token; this
// shape is just for picking out display strings.
type IDTokenSubjectClaims struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

// Logout removes tokens.json (and any extra paths the caller names —
// typically per-helper sub-caches like an STS-credentials dir or an
// SSH keys dir). config.json is intentionally preserved so a
// subsequent `login` can re-use the same issuer + client_id without
// re-typing flags.
//
// extras may be either absolute paths or paths relative to CacheDir.
// Missing files are not errors (best-effort cleanup).
func Logout(extras ...string) error {
	dir, err := CacheDir()
	if err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dir, "tokens.json"))
	for _, p := range extras {
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		_ = os.RemoveAll(p)
	}
	return nil
}

// SafeFilename collapses path-meaningful characters to '_' so an
// operator-supplied string (role slug, principal name, …) can safely
// be used as a leaf filename inside CacheDir. Empty input maps to
// "default" so callers always get a non-empty filename.
//
// Allowed set is [A-Za-z0-9._-]. Everything else — including '/',
// '\\', '.' adjacent to slashes, shell metacharacters — becomes '_'.
// The load-bearing property is "no path separator can appear in the
// output," which is exercised by oidcclient_test.go.
func SafeFilename(s string) string {
	b := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z',
			'A' <= c && c <= 'Z',
			'0' <= c && c <= '9',
			c == '-' || c == '_' || c == '.':
			b = append(b, c)
		default:
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "default"
	}
	return string(b)
}

// WriteFileAtomic writes data to a sibling tempfile and renames it
// over path, so a crash mid-write doesn't corrupt the existing file.
// mode is applied to the tempfile before rename so the file ends up
// with the intended permissions even on first-create.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	defer func() {
		// If rename succeeded, tmpName is gone and Remove is a no-op.
		// If we returned early, Remove cleans up the partial file.
		_ = os.Remove(tmpName)
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
