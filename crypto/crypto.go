// AES-256-GCM helpers and an envelope-encryption pattern.
//
// Layout:
//   - Seal/Open       — direct AEAD primitives (key + plaintext → ciphertext).
//   - RandomBytes     — single source of cryptographically random bytes.
//   - ParseKEK,
//     GenerateKEK     — parse / mint a 32-byte symmetric key encoded as 64 hex
//     characters. Suitable as a Key Encryption Key (KEK) or
//     any other 256-bit AES key.
//   - EncryptEnvelope,
//     DecryptEnvelope — envelope encryption: each call mints a fresh random Data
//     Encryption Key (DEK), encrypts the plaintext under it,
//     then wraps the DEK with a KeyProvider. Rotating the
//     master key only requires re-wrapping DEKs (Rewrap),
//     never re-encrypting the underlying values.
//
// Nonces are 96-bit and prepended to the ciphertext (output is `nonce || ct||tag`).
// With random nonces a single key is collision-safe up to ~2^32 messages — well
// beyond typical envelope-encryption budgets, but rotate keys before then if you
// expect to exceed it.
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// RandomBytes returns n cryptographically random bytes from crypto/rand.
// Used to mint master keys, DEKs, and AES-GCM nonces — any place uniformly
// random material is required.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ParseKEK decodes a 64-hex-character string into a 32-byte AES-256 key.
func ParseKEK(hexKey string) ([]byte, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid key encoding: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes (64 hex chars), got %d bytes", len(b))
	}
	return b, nil
}

// GenerateKEK returns a random 32-byte AES-256 key encoded as a 64-char hex
// string, ready for use with ParseKEK.
func GenerateKEK() (string, error) {
	b, err := RandomBytes(32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Seal encrypts plaintext with key using AES-256-GCM. The 96-bit nonce is
// generated freshly per call and prepended to the ciphertext, so the output
// format is `nonce || ciphertext+tag`.
func Seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	nonce, err := RandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts ciphertext produced by Seal. The input is expected to be
// `nonce || ciphertext+tag`.
func Open(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// EncryptEnvelope encrypts plaintext under a fresh random 32-byte DEK, then
// wraps the DEK using kp. Returns the encrypted value and the wrapped DEK.
// Each call produces a unique DEK, so identical plaintexts encrypt to distinct
// ciphertexts.
func EncryptEnvelope(ctx context.Context, kp KeyProvider, plaintext []byte) (encryptedValue, wrappedDEK []byte, err error) {
	dek, err := RandomBytes(32)
	if err != nil {
		return nil, nil, fmt.Errorf("generate dek: %w", err)
	}
	encryptedValue, err = Seal(dek, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("seal value: %w", err)
	}
	wrappedDEK, err = kp.Wrap(ctx, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap dek: %w", err)
	}
	return encryptedValue, wrappedDEK, nil
}

// DecryptEnvelope unwraps the DEK using kp, then decrypts the value under it.
func DecryptEnvelope(ctx context.Context, kp KeyProvider, wrappedDEK, encryptedValue []byte) ([]byte, error) {
	dek, err := kp.Unwrap(ctx, wrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	plaintext, err := Open(dek, encryptedValue)
	if err != nil {
		return nil, fmt.Errorf("decrypt value: %w", err)
	}
	return plaintext, nil
}

// Rewrap unwraps a wrapped DEK under oldKP and re-wraps it under newKP. Use
// this to rotate the master key without re-encrypting any values — DEKs and
// their ciphertexts remain valid; only the wrapper changes.
func Rewrap(ctx context.Context, oldKP, newKP KeyProvider, wrappedDEK []byte) ([]byte, error) {
	dek, err := oldKP.Unwrap(ctx, wrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	rewrapped, err := newKP.Wrap(ctx, dek)
	if err != nil {
		return nil, fmt.Errorf("rewrap dek: %w", err)
	}
	return rewrapped, nil
}
