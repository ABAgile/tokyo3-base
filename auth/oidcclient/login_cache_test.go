package oidcclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogin_FailedFlowPreservesCache(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	old := Config{Issuer: "https://old.example", ClientID: "old"}
	if err := SaveConfig(old); err != nil {
		t.Fatal(err)
	}
	tokens := &Tokens{AccessToken: "old", RefreshToken: "old-refresh", Expiration: time.Now().Add(time.Hour)}
	if err := SaveTokens(tokens); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 400) }))
	defer srv.Close()
	if _, err := Login(context.Background(), Config{Issuer: srv.URL, ClientID: "new"}, LoginOptions{Device: true, Stderr: io.Discard}); err == nil {
		t.Fatal("expected failed login")
	}
	cfg, err := LoadConfig()
	if err != nil || *cfg != old {
		t.Fatalf("config=%v error=%v", cfg, err)
	}
	cached, err := LoadTokens()
	if err != nil || cached.AccessToken != "old" {
		t.Fatalf("tokens=%v error=%v", cached, err)
	}
}

func TestEnsureFreshTokens_RejectsMismatchedBindingBeforeNetwork(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	bound := Config{Issuer: "https://old.example", ClientID: "old"}
	for _, expiry := range []time.Time{time.Now().Add(-time.Hour), time.Now().Add(time.Hour)} {
		if err := saveTokens(&Tokens{AccessToken: "old", RefreshToken: "secret", Expiration: expiry}, &bound); err != nil {
			t.Fatal(err)
		}
		for _, cfg := range []Config{{Issuer: "http://127.0.0.1:1", ClientID: "old"}, {Issuer: bound.Issuer, ClientID: "other"}} {
			if _, err := EnsureFreshTokens(context.Background(), cfg, time.Minute); err == nil || !strings.Contains(err.Error(), "mismatch") {
				t.Fatalf("error=%v", err)
			}
		}
	}
}

func TestLogin_PartialConfigSaveCannotRefreshWrongIssuer(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	recordDeviceSleeps(t)
	srv := devicePollServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"access_token":"new","refresh_token":"secret","expires_in":3600}`)
	})
	dir, err := CacheDir()
	if err != nil {
		t.Fatal(err)
	}
	// A directory at config.json prevents the final rename, after tokens save.
	if err := os.Mkdir(filepath.Join(dir, "config.json"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Issuer: srv.URL, ClientID: "new"}
	if _, err := Login(context.Background(), cfg, LoginOptions{Device: true}); err == nil {
		t.Fatal("expected persistence failure")
	}
	if _, err := EnsureFreshTokens(context.Background(), Config{Issuer: "https://old.example", ClientID: "old"}, time.Minute); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("error=%v", err)
	}
}
