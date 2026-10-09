package sealedcookie

import (
	"errors"
	"testing"

	"github.com/abagile/tokyo3-base/internal/randtest"
)

func TestSeal_FailsWithoutValueWhenNonceCannotBeDrawn(t *testing.T) {
	var out string
	var err error
	randtest.FailAfter(t, 0, func() { out, err = Seal(testKey, payload{A: "x", B: 7}) })
	if !errors.Is(err, randtest.ErrEntropy) {
		t.Fatalf("err = %v, want the entropy error", err)
	}
	if out != "" {
		t.Errorf("Seal returned %q alongside the error", out)
	}
}
