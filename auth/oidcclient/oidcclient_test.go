package oidcclient_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/auth/oidcclient"
)

func TestSafeFilename(t *testing.T) {
	cases := map[string]string{
		"tokyo3-platform-prod":  "tokyo3-platform-prod",
		"with.dots":             "with.dots",
		"with/slash":            "with_slash",
		"../../../etc/passwd":   ".._.._.._etc_passwd",
		"a b c":                 "a_b_c",
		"":                      "default",
		"unicode-嗨":             "unicode-___",
		"shell$injection`echo`": "shell_injection_echo_",
	}
	for in, want := range cases {
		if got := oidcclient.SafeFilename(in); got != want {
			t.Errorf("SafeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSafeFilename_NoPathSeparators is the load-bearing safety
// property: no input produces an output containing a path separator,
// so writes against `<cachedir>/<result>.json` cannot escape the
// cache directory.
func TestSafeFilename_NoPathSeparators(t *testing.T) {
	for _, in := range []string{
		"../etc", "/etc/passwd", "..\\windows", "foo/bar/baz", "..\\..\\x",
	} {
		got := oidcclient.SafeFilename(in)
		if strings.ContainsAny(got, "/\\") {
			t.Errorf("SafeFilename(%q) = %q — contains path separator", in, got)
		}
	}
}

func TestBuildAuthorizeURL_PKCEAndScopes(t *testing.T) {
	u := oidcclient.BuildAuthorizeURL("https://id.example.com", "tokyo3-cli",
		"http://127.0.0.1:54321/callback", "test-state", "test-challenge")
	wants := []string{
		"https://id.example.com/authorize?",
		"client_id=tokyo3-cli",
		"response_type=code",
		"code_challenge=test-challenge",
		"code_challenge_method=S256",
		"state=test-state",
		"redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fcallback",
		"scope=openid+email+profile+offline_access",
	}
	for _, w := range wants {
		if !strings.Contains(u, w) {
			t.Errorf("BuildAuthorizeURL missing %q in %s", w, u)
		}
	}
}

// TestBuildAuthorizeURL_TrailingSlashIssuer guards against a
// double-slash in the URL when the issuer ends with a slash (common
// operator typo).
func TestBuildAuthorizeURL_TrailingSlashIssuer(t *testing.T) {
	u := oidcclient.BuildAuthorizeURL("https://id.example.com/", "c", "http://x", "s", "ch")
	if strings.Contains(u, "//authorize") {
		t.Errorf("double-slash in authorize URL: %s", u)
	}
}

func TestIDTokenClaims_PicksOutSubAndEmail(t *testing.T) {
	// A JWT is `header.payload.signature`; only the middle segment
	// matters here because IDTokenClaims doesn't verify.
	payload := map[string]any{
		"sub":   "alice-uuid",
		"email": "alice@example.com",
		"name":  "Alice",
		"iss":   "https://id.example.com",
	}
	pb, _ := json.Marshal(payload)
	token := "header." + base64.RawURLEncoding.EncodeToString(pb) + ".sig"

	got := oidcclient.IDTokenClaims(token)
	if got.Subject != "alice-uuid" {
		t.Errorf("Subject = %q, want alice-uuid", got.Subject)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("Email = %q", got.Email)
	}
	if got.Name != "Alice" {
		t.Errorf("Name = %q", got.Name)
	}
}

func TestIDTokenClaims_MalformedReturnsZero(t *testing.T) {
	for _, in := range []string{
		"",
		"not-a-jwt",
		"only.two",
		"a.!!notbase64!!.c",
	} {
		got := oidcclient.IDTokenClaims(in)
		if got.Subject != "" || got.Email != "" {
			t.Errorf("IDTokenClaims(%q) = %+v, want zero", in, got)
		}
	}
}

func TestConfigAndTokensRoundtrip(t *testing.T) {
	// Redirect XDG_CONFIG_HOME so the test doesn't touch the dev's
	// real config dir. CacheDir respects os.UserConfigDir, which
	// honors XDG_CONFIG_HOME on Linux.
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	// On macOS UserConfigDir uses ~/Library/Application Support; setting
	// HOME to tmp covers that path so the test still isolates writes.
	t.Setenv("HOME", tmp)

	cfg := oidcclient.Config{Issuer: "https://id.example.com", ClientID: "c"}
	if err := oidcclient.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got, err := oidcclient.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if *got != cfg {
		t.Errorf("LoadConfig = %+v, want %+v", *got, cfg)
	}

	tokens := &oidcclient.Tokens{
		AccessToken:  "at",
		RefreshToken: "rt",
		IDToken:      "it",
		Expiration:   time.Now().Add(time.Hour).Round(time.Second).UTC(),
	}
	if err := oidcclient.SaveTokens(tokens); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}
	gotT, err := oidcclient.LoadTokens()
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}
	if gotT.AccessToken != "at" || gotT.RefreshToken != "rt" || gotT.IDToken != "it" {
		t.Errorf("LoadTokens = %+v", gotT)
	}
	if !gotT.Expiration.Equal(tokens.Expiration) {
		t.Errorf("Expiration round-trip lost: %v vs %v", gotT.Expiration, tokens.Expiration)
	}

	// Tokens file must be 0o600.
	dir, _ := oidcclient.CacheDir()
	info, err := os.Stat(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatalf("stat tokens.json: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("tokens.json mode = %v, want 0o600", mode)
	}
}

// TestLoadTokens_MissingFileReturnsRunLoginMessage pins the user-facing
// error text that the helpers print verbatim when there's no SSO cache
// at all. The "run login" hint is the migration story for users coming
// from the per-helper cache layout — no automatic detection, just a
// clear prompt to re-authenticate.
func TestLoadTokens_MissingFileReturnsRunLoginMessage(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp)

	_, err := oidcclient.LoadTokens()
	if err == nil {
		t.Fatal("LoadTokens with no file: want error, got nil")
	}
	if !strings.Contains(err.Error(), "run login") {
		t.Errorf("error %q does not mention 'run login'", err.Error())
	}
}

// TestAppCacheDir_RootedUnderSharedDir verifies the unified-cache
// contract: every helper's sub-dir lives under one shared root, so a
// single login serves all of them. Path separators in appName are
// rejected so a malicious operator config can't escape the root.
func TestAppCacheDir_RootedUnderSharedDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp)

	root, err := oidcclient.CacheDir()
	if err != nil {
		t.Fatalf("CacheDir: %v", err)
	}
	for _, name := range []string{"aws-creds", "ssh-creds", "vault-creds"} {
		got, err := oidcclient.AppCacheDir(name)
		if err != nil {
			t.Fatalf("AppCacheDir(%q): %v", name, err)
		}
		want := filepath.Join(root, name)
		if got != want {
			t.Errorf("AppCacheDir(%q) = %q, want %q", name, got, want)
		}
		if info, err := os.Stat(got); err != nil {
			t.Errorf("AppCacheDir(%q) not created: %v", name, err)
		} else if mode := info.Mode().Perm(); mode != 0o700 {
			t.Errorf("AppCacheDir(%q) mode = %v, want 0o700", name, mode)
		}
	}

	// Path-separator escape attempts: must error rather than silently
	// resolving to an unintended directory.
	for _, bad := range []string{"", "..", "../etc", "foo/bar", "a\\b"} {
		if _, err := oidcclient.AppCacheDir(bad); err == nil {
			t.Errorf("AppCacheDir(%q): expected error, got nil", bad)
		}
	}
}

func TestLogout_KeepsConfig(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp)

	if err := oidcclient.SaveConfig(oidcclient.Config{Issuer: "i", ClientID: "c"}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	if err := oidcclient.SaveTokens(&oidcclient.Tokens{AccessToken: "a"}); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}
	// An extra sub-cache that Logout should also wipe.
	dir, _ := oidcclient.CacheDir()
	extra := filepath.Join(dir, "sub")
	if err := os.MkdirAll(extra, 0o700); err != nil {
		t.Fatalf("mkdir extra: %v", err)
	}
	if err := os.WriteFile(filepath.Join(extra, "x"), []byte("z"), 0o600); err != nil {
		t.Fatalf("write extra: %v", err)
	}

	if err := oidcclient.Logout("sub"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tokens.json")); !os.IsNotExist(err) {
		t.Errorf("tokens.json should be gone, err=%v", err)
	}
	if _, err := os.Stat(extra); !os.IsNotExist(err) {
		t.Errorf("extra sub-cache should be gone, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Errorf("config.json should still exist, err=%v", err)
	}
}

// TestRefresh_HappyPath spins up an httptest server emulating the
// /token endpoint and checks that Refresh wires the request and
// decodes the response correctly.
func TestRefresh_HappyPath(t *testing.T) {
	var captured url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		captured = r.PostForm
		_, _ = w.Write([]byte(`{
			"access_token": "new-at",
			"refresh_token": "new-rt",
			"id_token": "new-it",
			"expires_in": 3600
		}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	got, err := oidcclient.Refresh(ctx, srv.URL, "client-x", "old-rt")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got.AccessToken != "new-at" || got.RefreshToken != "new-rt" || got.IDToken != "new-it" {
		t.Errorf("Refresh returned %+v", got)
	}
	if d := time.Until(got.Expiration); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("Expiration ~ %v, want ~1h from now", d)
	}
	if captured.Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type = %q", captured.Get("grant_type"))
	}
	if captured.Get("client_id") != "client-x" {
		t.Errorf("client_id = %q", captured.Get("client_id"))
	}
	if captured.Get("refresh_token") != "old-rt" {
		t.Errorf("refresh_token = %q", captured.Get("refresh_token"))
	}
}

// TestEnsureFreshTokens_KeepsRefreshTokenWhenServerOmits guards the
// "rotation disabled" path: when /token doesn't echo refresh_token,
// EnsureFreshTokens must retain the previously-cached value.
func TestEnsureFreshTokens_KeepsRefreshTokenWhenServerOmits(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"new-at","expires_in":3600}`))
	}))
	defer srv.Close()

	cfg := oidcclient.Config{Issuer: srv.URL, ClientID: "c"}
	if err := oidcclient.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	// Stale tokens so EnsureFreshTokens hits the refresh path.
	if err := oidcclient.SaveTokens(&oidcclient.Tokens{
		AccessToken:  "old",
		RefreshToken: "kept-rt",
		IDToken:      "kept-it",
		Expiration:   time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	got, err := oidcclient.EnsureFreshTokens(t.Context(), cfg, 30*time.Second)
	if err != nil {
		t.Fatalf("EnsureFreshTokens: %v", err)
	}
	if got.AccessToken != "new-at" {
		t.Errorf("AccessToken = %q", got.AccessToken)
	}
	if got.RefreshToken != "kept-rt" {
		t.Errorf("RefreshToken = %q, want previous kept-rt (server omitted rotation)", got.RefreshToken)
	}
	if got.IDToken != "kept-it" {
		t.Errorf("IDToken = %q, want previous kept-it (refresh response had no id_token)", got.IDToken)
	}
}

func TestEnsureFreshTokens_ReturnsCachedWhenWithinSkew(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp)

	// /token must NOT be reachable — we expect EnsureFreshTokens to
	// skip the refresh entirely.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("unexpected call to /token; refresh should have been skipped")
		http.Error(w, "no", 500)
	}))
	defer srv.Close()

	cfg := oidcclient.Config{Issuer: srv.URL, ClientID: "c"}
	_ = oidcclient.SaveConfig(cfg)
	_ = oidcclient.SaveTokens(&oidcclient.Tokens{
		AccessToken:  "still-good",
		RefreshToken: "rt",
		Expiration:   time.Now().Add(time.Hour),
	})
	got, err := oidcclient.EnsureFreshTokens(t.Context(), cfg, 30*time.Second)
	if err != nil {
		t.Fatalf("EnsureFreshTokens: %v", err)
	}
	if got.AccessToken != "still-good" {
		t.Errorf("AccessToken = %q, want still-good (no refresh)", got.AccessToken)
	}
}

func TestWriteFileAtomic_SetsModeAndContent(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "secret.json")
	if err := oidcclient.WriteFileAtomic(path, []byte("payload"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %v, want 0o600", mode)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "payload" {
		t.Errorf("content = %q", got)
	}
}
