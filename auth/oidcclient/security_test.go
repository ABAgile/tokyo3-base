package oidcclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequireSecureEndpoint(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://idp.example/token": true,
		"http://127.0.0.1:8080/t":   true,
		"http://[::1]:8080/t":       true,
		"http://localhost/t":        true,
		"http://idp.example/token":  false,
		"http://10.0.0.5/token":     false,
		"ftp://idp.example/t":       false,
		"/token":                    false,
	} {
		if err := requireSecureEndpoint(raw); (err == nil) != ok {
			t.Errorf("requireSecureEndpoint(%q) = %v, want ok=%v", raw, err, ok)
		}
	}
}

func TestPostForm_RefusesCleartextRemoteEndpoint(t *testing.T) {
	_, err := PostTokenAt(context.Background(), "http://idp.example/token", url.Values{"refresh_token": {"secret"}})
	if err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("err = %v, want non-https refusal", err)
	}
}

func TestPostForm_DoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	if _, err := PostTokenAt(context.Background(), redir.URL, url.Values{"refresh_token": {"secret"}}); err == nil {
		t.Fatal("expected error for redirect response")
	}
	if hits.Load() != 0 {
		t.Fatal("credential-bearing POST was redirected")
	}
}

func TestDiscoverEndpoints_IgnoresCleartextRemoteEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token_endpoint":"http://evil.example/token","authorization_endpoint":"https://idp.example/auth"}`))
	}))
	defer srv.Close()
	ep := discoverEndpoints(context.Background(), srv.URL)
	if want := srv.URL + "/token"; ep.TokenEndpoint != want {
		t.Errorf("TokenEndpoint = %q, want convention fallback %q", ep.TokenEndpoint, want)
	}
	if ep.AuthorizationEndpoint != "https://idp.example/auth" {
		t.Errorf("AuthorizationEndpoint = %q, want discovered https endpoint", ep.AuthorizationEndpoint)
	}
}

func TestEnsureFreshTokens_ConcurrentRefreshesSerialised(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var refreshes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		// One-shot rotation: a reused refresh token is rejected.
		_ = r.ParseForm()
		if r.PostForm.Get("refresh_token") != "rt-old" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		refreshes.Add(1)
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`{"access_token":"at-new","refresh_token":"rt-new","expires_in":3600}`))
	}))
	defer srv.Close()
	cfg := Config{Issuer: srv.URL, ClientID: "c"}
	if err := saveTokens(&Tokens{AccessToken: "at-old", RefreshToken: "rt-old", Expiration: time.Now().Add(-time.Hour)}, &cfg); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			got, err := EnsureFreshTokens(context.Background(), cfg, time.Minute)
			if err == nil && got.AccessToken != "at-new" {
				t.Errorf("AccessToken = %q, want at-new", got.AccessToken)
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("EnsureFreshTokens: %v", err)
		}
	}
	if n := refreshes.Load(); n != 1 {
		t.Errorf("refresh calls = %d, want 1", n)
	}
}

func TestCacheDir_TightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	loose := base + "/" + rootDirName
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := CacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v, err = %v; want 0700", fi.Mode().Perm(), err)
	}
}

func TestLoopbackCallback_IgnoredRequestKeepsWaiting(t *testing.T) {
	ln, uri, err := LoopbackListener(0, "/cb")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lc := StartLoopbackCallback(ln, "/cb", func(w http.ResponseWriter, r *http.Request) (string, error) {
		if r.URL.Query().Get("ok") == "" {
			return "", ErrCallbackIgnored
		}
		return "good", nil
	})
	for _, q := range []string{"", "?ok=1"} {
		resp, err := http.Get(uri + q)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	got, err := lc.Wait(context.Background(), time.Second)
	if err != nil || got != "good" {
		t.Fatalf("Wait = %q, %v; want good", got, err)
	}
}
