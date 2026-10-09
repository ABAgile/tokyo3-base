package oidcclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// isolateConfigHome points the user config dir at a temp directory on every
// platform. os.UserConfigDir reads XDG_CONFIG_HOME on Linux but HOME on macOS.
func isolateConfigHome(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("HOME", base)
	return base
}

// PostToken adds the /token convention to an issuer. A trailing slash on the
// issuer must not produce a double slash in the endpoint.
func TestPostToken_UsesTokenPathUnderIssuer(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"access_token":"at","expires_in":60}`))
	}))
	defer srv.Close()

	tok, err := PostToken(context.Background(), srv.URL+"/", url.Values{"grant_type": {"refresh_token"}})
	if err != nil {
		t.Fatalf("PostToken: %v", err)
	}
	if gotPath != "/token" {
		t.Errorf("token request path = %q, want /token", gotPath)
	}
	if tok.AccessToken != "at" {
		t.Errorf("AccessToken = %q, want at", tok.AccessToken)
	}
}

func TestPostTokenAt_RejectsNonJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>maintenance</html>"))
	}))
	defer srv.Close()

	_, err := PostTokenAt(context.Background(), srv.URL, url.Values{})
	if err == nil || !strings.Contains(err.Error(), "decode token response") {
		t.Fatalf("err = %v, want a decode error", err)
	}
}

// A 200 response with no access token must not produce a usable Tokens.
func TestPostTokenAt_RejectsResponseWithoutAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	tok, err := PostTokenAt(context.Background(), srv.URL, url.Values{})
	if err == nil || !strings.Contains(err.Error(), "no access_token") {
		t.Fatalf("err = %v, tok = %+v; want a missing-access-token error", err, tok)
	}
	if tok != nil {
		t.Errorf("tok = %+v, want nil alongside the error", tok)
	}
}

func TestPostTokenAt_RejectsMalformedEndpoint(t *testing.T) {
	_, err := PostTokenAt(context.Background(), "http://[::1", url.Values{})
	if err == nil || !strings.Contains(err.Error(), "invalid endpoint") {
		t.Fatalf("err = %v, want an invalid-endpoint error", err)
	}
}

// With no config dir resolvable, every cache entry point fails instead of
// falling back to a path in the working directory.
func TestCacheDirs_FailWithoutAHomeDirectory(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if dir, err := CacheDir(); err == nil {
		t.Errorf("CacheDir() = %q, want an error without a config directory", dir)
	}
	if dir, err := AppCacheDir("app"); err == nil {
		t.Errorf("AppCacheDir() = %q, want an error without a config directory", dir)
	}
}

// If the cache root exists as a regular file, the cache cannot be created.
// The error must surface rather than silently using a different location.
func TestCacheDir_FailsWhenRootIsAFile(t *testing.T) {
	base := isolateConfigHome(t)
	if err := os.WriteFile(filepath.Join(base, rootDirName), []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	if dir, err := CacheDir(); err == nil {
		t.Errorf("CacheDir() = %q, want an error when the root is a file", dir)
	}
}

func TestAppCacheDir_FailsWhenAppPathIsAFile(t *testing.T) {
	base := isolateConfigHome(t)
	root := filepath.Join(base, rootDirName)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app"), []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	if dir, err := AppCacheDir("app"); err == nil {
		t.Errorf("AppCacheDir() = %q, want an error when the app path is a file", dir)
	}
}

func TestWriteFileAtomic_AppliesModeAndLeavesNoTempFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(path, []byte("secret-token"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600 (the requested mode replaces the old one)", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(path); string(b) != "secret-token" {
		t.Errorf("content = %q", b)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only tokens.json (no leftover temp file)", names)
	}
}

// A write that cannot create its temp file must fail without creating the
// missing directory or any partial file.
func TestWriteFileAtomic_FailsIntoMissingDirectoryWithoutLeftovers(t *testing.T) {
	parent := t.TempDir()
	missing := filepath.Join(parent, "absent")
	if err := WriteFileAtomic(filepath.Join(missing, "tokens.json"), []byte("x"), 0o600); err == nil {
		t.Fatal("WriteFileAtomic into a missing directory returned nil")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("failed write created %s (stat err = %v)", missing, err)
	}
}
