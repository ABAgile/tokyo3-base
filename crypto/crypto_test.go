package crypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestParseKEK(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "valid 64-char hex",
			input: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		},
		{
			name:    "too short",
			input:   "deadbeef",
			wantErr: true,
		},
		{
			name:    "too long",
			input:   "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
			wantErr: true,
		},
		{
			name:    "non-hex characters",
			input:   "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKEK(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != 32 {
				t.Errorf("key length = %d, want 32", len(got))
			}
		})
	}
}

func TestGenerateKEK(t *testing.T) {
	a, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	if len(a) != 64 {
		t.Errorf("len = %d, want 64", len(a))
	}

	// Two calls should produce different keys.
	b, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK second call: %v", err)
	}
	if a == b {
		t.Error("two GenerateKEK calls returned the same key")
	}

	// Generated key must parse successfully.
	if _, err := ParseKEK(a); err != nil {
		t.Errorf("generated key failed ParseKEK: %v", err)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ctx := context.Background()
	kekHex, _ := GenerateKEK()
	kek, _ := ParseKEK(kekHex)
	kp := NewLocalKeyProvider(kek)

	plaintexts := []string{
		"",
		"short",
		"postgres://user:pass@host:5432/db",
		"a secret with spaces and symbols: !@#$%^&*()",
		string(make([]byte, 4096)), // large value
	}

	for _, pt := range plaintexts {
		label := pt
		if len(label) > 20 {
			label = label[:20]
		}
		t.Run(label, func(t *testing.T) {
			encVal, encDEK, err := EncryptEnvelope(ctx, kp, []byte(pt))
			if err != nil {
				t.Fatalf("EncryptEnvelope: %v", err)
			}

			got, err := DecryptEnvelope(ctx, kp, encDEK, encVal)
			if err != nil {
				t.Fatalf("DecryptEnvelope: %v", err)
			}

			if !bytes.Equal(got, []byte(pt)) {
				t.Errorf("decrypted value mismatch:\ngot  %q\nwant %q", got, pt)
			}
		})
	}
}

func TestEncryptProducesUniqueCiphertexts(t *testing.T) {
	ctx := context.Background()
	kekHex, _ := GenerateKEK()
	kek, _ := ParseKEK(kekHex)
	kp := NewLocalKeyProvider(kek)
	pt := []byte("same plaintext")

	enc1, _, err := EncryptEnvelope(ctx, kp, pt)
	if err != nil {
		t.Fatal(err)
	}
	enc2, _, err := EncryptEnvelope(ctx, kp, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc1, enc2) {
		t.Error("two encryptions of the same value produced identical ciphertexts (nonce reuse)")
	}
}

func TestDecryptWithWrongKEK(t *testing.T) {
	ctx := context.Background()
	kekHex, _ := GenerateKEK()
	kek, _ := ParseKEK(kekHex)
	kp := NewLocalKeyProvider(kek)

	wrongHex, _ := GenerateKEK()
	wrongKEK, _ := ParseKEK(wrongHex)
	wrongKP := NewLocalKeyProvider(wrongKEK)

	encVal, encDEK, err := EncryptEnvelope(ctx, kp, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptEnvelope(ctx, wrongKP, encDEK, encVal)
	if err == nil {
		t.Error("expected error decrypting with wrong KEK, got nil")
	}
}

func TestRewrap(t *testing.T) {
	ctx := context.Background()
	oldHex, _ := GenerateKEK()
	oldKEK, _ := ParseKEK(oldHex)
	oldKP := NewLocalKeyProvider(oldKEK)

	newHex, _ := GenerateKEK()
	newKEK, _ := ParseKEK(newHex)
	newKP := NewLocalKeyProvider(newKEK)

	plaintext := []byte("my secret value")
	encVal, encDEK, err := EncryptEnvelope(ctx, oldKP, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Rewrap the DEK under the new master key.
	newEncDEK, err := Rewrap(ctx, oldKP, newKP, encDEK)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	// Old DEK ciphertext and new should differ.
	if bytes.Equal(encDEK, newEncDEK) {
		t.Error("rewrapped DEK is identical to original")
	}

	// Decrypting the original ciphertext with the rewrapped DEK should work.
	got, err := DecryptEnvelope(ctx, newKP, newEncDEK, encVal)
	if err != nil {
		t.Fatalf("DecryptEnvelope after rewrap: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("got %q, want %q", got, plaintext)
	}

	// Old KEK must no longer decrypt.
	_, err = DecryptEnvelope(ctx, oldKP, newEncDEK, encVal)
	if err == nil {
		t.Error("expected error using old KEK on rewrapped DEK")
	}
}

// TestDecryptEnvelope_ShortCiphertext tests the "ciphertext too short" path.
func TestDecryptEnvelope_ShortCiphertext(t *testing.T) {
	ctx := context.Background()
	kekHex, _ := GenerateKEK()
	kek, _ := ParseKEK(kekHex)
	kp := NewLocalKeyProvider(kek)

	// Generate a valid DEK.
	_, encDEK, err := EncryptEnvelope(ctx, kp, []byte("plaintext"))
	if err != nil {
		t.Fatal(err)
	}

	// Use a 1-byte "ciphertext" — too short for GCM nonce.
	_, err = DecryptEnvelope(ctx, kp, encDEK, []byte{0x01})
	if err == nil {
		t.Error("expected error for too-short ciphertext, got nil")
	}
}

// TestRewrap_UnwrapError tests the error path when unwrap fails.
func TestRewrap_UnwrapError(t *testing.T) {
	ctx := context.Background()
	kekHex, _ := GenerateKEK()
	kek, _ := ParseKEK(kekHex)
	kp := NewLocalKeyProvider(kek)

	newHex, _ := GenerateKEK()
	newKEK, _ := ParseKEK(newHex)
	newKP := NewLocalKeyProvider(newKEK)

	// Pass garbage as wrappedDEK so unwrap fails.
	_, err := Rewrap(ctx, kp, newKP, []byte("garbage-not-a-real-ciphertext"))
	if err == nil {
		t.Error("expected error from Rewrap with invalid DEK ciphertext, got nil")
	}
}

// TestSeal_ShortKey covers the aes.NewCipher error path: AES requires a
// 16/24/32-byte key, so a 5-byte input must error.
func TestSeal_ShortKey(t *testing.T) {
	if _, err := Seal([]byte("short"), []byte("hi")); err == nil {
		t.Error("expected error sealing with a short key, got nil")
	}
}

// TestOpen_ShortKey is the symmetric case for Open's aes.NewCipher branch.
func TestOpen_ShortKey(t *testing.T) {
	// 12-byte payload satisfies the nonce-length check so we reach aes.NewCipher.
	if _, err := Open([]byte("short"), make([]byte, 12)); err == nil {
		t.Error("expected error opening with a short key, got nil")
	}
}

// wrapFailKP succeeds at Unwrap (returning a valid 32-byte key) but always
// fails at Wrap. Lets us cover the Wrap-error branches in EncryptEnvelope and
// Rewrap without resorting to a fully bespoke mock.
type wrapFailKP struct{}

func (wrapFailKP) Wrap(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("wrap unavailable")
}
func (wrapFailKP) Unwrap(context.Context, []byte) ([]byte, error) {
	return make([]byte, 32), nil
}

func TestEncryptEnvelope_WrapError(t *testing.T) {
	_, _, err := EncryptEnvelope(context.Background(), wrapFailKP{}, []byte("data"))
	if err == nil {
		t.Error("expected error when KeyProvider.Wrap fails, got nil")
	}
}

func TestRewrap_WrapError(t *testing.T) {
	// Stub oldKP returns a valid DEK on Unwrap; newKP fails Wrap.
	_, err := Rewrap(context.Background(), wrapFailKP{}, wrapFailKP{}, []byte("ciphertext"))
	if err == nil {
		t.Error("expected error when newKP.Wrap fails, got nil")
	}
}
