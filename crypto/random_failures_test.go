package crypto

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/internal/randtest"
)

// A failed random draw must return no key or ciphertext alongside the error. A
// partial result would look like a usable secret to the caller.

func TestRandomBytes_FailsWithoutBytes(t *testing.T) {
	var b []byte
	var err error
	randtest.FailAfter(t, 0, func() { b, err = RandomBytes(16) })
	if !errors.Is(err, randtest.ErrEntropy) {
		t.Fatalf("err = %v, want the entropy error", err)
	}
	if b != nil {
		t.Errorf("RandomBytes returned %d bytes alongside the error", len(b))
	}
}

func TestGenerateKEK_FailsWithoutKey(t *testing.T) {
	var kek string
	var err error
	randtest.FailAfter(t, 0, func() { kek, err = GenerateKEK() })
	if !errors.Is(err, randtest.ErrEntropy) {
		t.Fatalf("err = %v, want the entropy error", err)
	}
	if kek != "" {
		t.Errorf("GenerateKEK returned %q alongside the error", kek)
	}
}

func TestSealAAD_FailsWithoutCiphertextWhenNonceCannotBeDrawn(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	var out []byte
	var err error
	randtest.FailAfter(t, 0, func() { out, err = SealAAD(key, []byte("plaintext"), nil) })
	if !errors.Is(err, randtest.ErrEntropy) {
		t.Fatalf("err = %v, want the entropy error", err)
	}
	if !strings.Contains(err.Error(), "generate nonce") {
		t.Errorf("err = %v, want the nonce step named", err)
	}
	if out != nil {
		t.Errorf("SealAAD returned %d bytes alongside the error", len(out))
	}
}

// EncryptEnvelopeAAD draws the DEK first, then the value nonce. Each case fails
// at a different draw, and every case must return no ciphertext and no wrapped
// key.
func TestEncryptEnvelopeAAD_FailsWithoutPartialOutput(t *testing.T) {
	kp := NewLocalKeyProvider(bytes.Repeat([]byte{2}, 32))
	// Each case names the step that must fail. The step matters: a later draw
	// (the key wrap's nonce) would also fail and hide an ignored earlier error.
	cases := []struct {
		name  string
		reads int // successful reads before the failure
		step  string
	}{
		{"DEK cannot be drawn", 0, "generate dek"},
		{"value nonce cannot be drawn after the DEK", 1, "seal value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ct, wrapped []byte
			var err error
			randtest.FailAfter(t, tc.reads, func() {
				ct, wrapped, err = EncryptEnvelopeAAD(context.Background(), kp, []byte("secret"), nil)
			})
			if !errors.Is(err, randtest.ErrEntropy) || !strings.Contains(err.Error(), tc.step) {
				t.Fatalf("err = %v, want the entropy error from %q", err, tc.step)
			}
			if ct != nil || wrapped != nil {
				t.Errorf("returned ciphertext %d bytes, wrapped key %d bytes alongside the error", len(ct), len(wrapped))
			}
		})
	}
}
