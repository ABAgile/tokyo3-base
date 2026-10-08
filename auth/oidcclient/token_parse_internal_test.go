package oidcclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseTokens_MissingExpiresInGetsDefaultTTL(t *testing.T) {
	tok, err := parseTokens([]byte(`{"access_token":"a","refresh_token":"r"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Until(tok.Expiration); got < defaultTokenTTL-time.Minute || got > defaultTokenTTL {
		t.Fatalf("Expiration in %v, want about %v", got, defaultTokenTTL)
	}
	tok, err = parseTokens([]byte(`{"access_token":"a","expires_in":120}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Until(tok.Expiration); got > 2*time.Minute || got < time.Minute {
		t.Fatalf("explicit expires_in ignored: %v", got)
	}
}

func TestPostTokenAt_TruncatesErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	defer srv.Close()
	_, err := PostTokenAt(t.Context(), srv.URL, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if len(err.Error()) > maxErrorBody+100 {
		t.Fatalf("error is %d bytes, want it bounded", len(err.Error()))
	}
}
