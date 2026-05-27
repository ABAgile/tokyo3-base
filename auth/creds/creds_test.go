package creds

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestHashPassword_RoundTrip(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
	if strings.Contains(hash, "correct-horse-battery-staple") {
		t.Fatal("hash leaks plaintext")
	}
	if !CheckPassword(hash, "correct-horse-battery-staple") {
		t.Error("CheckPassword: correct password rejected")
	}
	if CheckPassword(hash, "wrong-password") {
		t.Error("CheckPassword: wrong password accepted")
	}
}

func TestHashPassword_DistinctSalts(t *testing.T) {
	h1, err := HashPassword("samepw")
	if err != nil {
		t.Fatalf("HashPassword 1: %v", err)
	}
	h2, err := HashPassword("samepw")
	if err != nil {
		t.Fatalf("HashPassword 2: %v", err)
	}
	if h1 == h2 {
		t.Error("bcrypt should produce distinct hashes for identical input (salt)")
	}
	if !CheckPassword(h1, "samepw") || !CheckPassword(h2, "samepw") {
		t.Error("both hashes should verify the same password")
	}
}

func TestCheckPassword_RejectsGarbageHash(t *testing.T) {
	if CheckPassword("not-a-bcrypt-hash", "anything") {
		t.Error("CheckPassword should reject malformed hash")
	}
	if CheckPassword("", "anything") {
		t.Error("CheckPassword should reject empty hash")
	}
}

func TestGenerateRawToken_Shape(t *testing.T) {
	tok, err := GenerateRawToken()
	if err != nil {
		t.Fatalf("GenerateRawToken: %v", err)
	}
	if len(tok) != 64 {
		t.Errorf("token length: want 64 hex chars, got %d", len(tok))
	}
	if _, err := hex.DecodeString(tok); err != nil {
		t.Errorf("token is not valid hex: %v", err)
	}
}

func TestGenerateRawToken_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 32)
	for i := range 32 {
		tok, err := GenerateRawToken()
		if err != nil {
			t.Fatalf("GenerateRawToken: %v", err)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token after %d iterations", i)
		}
		seen[tok] = struct{}{}
	}
}

func TestHashToken_DeterministicAndShape(t *testing.T) {
	a := HashToken("opaque-bearer")
	b := HashToken("opaque-bearer")
	if a != b {
		t.Errorf("HashToken must be deterministic: %q vs %q", a, b)
	}
	if len(a) != 64 {
		t.Errorf("HashToken output: want 64 hex chars (sha256), got %d", len(a))
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Errorf("HashToken output is not valid hex: %v", err)
	}
	if HashToken("opaque-bearer") == HashToken("opaque-bearer-2") {
		t.Error("distinct inputs hashed to the same digest")
	}
}
