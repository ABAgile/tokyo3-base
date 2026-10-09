package oidcclient

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// With no config directory resolvable, every cache operation must fail rather
// than write to a fallback location.
func TestCacheOperations_FailWithoutAHomeDirectory(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	cfg := Config{Issuer: "https://idp.example", ClientID: "client"}
	if err := SaveConfig(cfg); err == nil {
		t.Error("SaveConfig succeeded without a config directory")
	}
	if _, err := LoadConfig(); err == nil {
		t.Error("LoadConfig succeeded without a config directory")
	}
	if err := SaveTokens(&Tokens{AccessToken: "at"}); err == nil {
		t.Error("SaveTokens succeeded without a config directory")
	}
	if _, err := LoadTokens(); err == nil {
		t.Error("LoadTokens succeeded without a config directory")
	}
	if err := Logout(); err == nil {
		t.Error("Logout succeeded without a config directory")
	}
}

// A config file that is not JSON, or that lacks the issuer or client ID, must
// not be used to build a login.
func TestLoadConfig_RejectsCorruptAndIncompleteFiles(t *testing.T) {
	base := isolateConfigHome(t)
	dir := filepath.Join(base, rootDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	for name, body := range map[string]string{
		"not JSON":          "{not json",
		"missing client_id": `{"issuer":"https://idp.example"}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if cfg, err := LoadConfig(); err == nil {
			t.Errorf("%s: LoadConfig = %+v, want an error", name, cfg)
		}
	}
}

// A cache that cannot be read as a file, or cannot be decoded, is an error.
// It must never be taken for an empty cache.
func TestLoadTokens_RejectsUnreadableOrCorruptCache(t *testing.T) {
	base := isolateConfigHome(t)
	dir := filepath.Join(base, rootDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tokens.json")

	// A directory where the file should be: the read fails, and not because the
	// file is absent.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if tok, err := LoadTokens(); err == nil {
		t.Errorf("LoadTokens on a directory = %+v, want an error", tok)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, err := LoadTokens(); err == nil {
		t.Errorf("LoadTokens on corrupt JSON = %+v, want an error", tok)
	}
}

// With no cached login at all, a refresh must say so rather than return zero
// tokens.
func TestEnsureFreshTokens_NoCacheIsAnError(t *testing.T) {
	isolateConfigHome(t)
	cfg := Config{Issuer: "https://idp.example", ClientID: "client"}
	if tok, err := EnsureFreshTokens(context.Background(), cfg, time.Minute); err == nil {
		t.Errorf("EnsureFreshTokens with no cache = %+v, want an error", tok)
	}
}
