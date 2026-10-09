package creds

import (
	"errors"
	"testing"

	"github.com/abagile/tokyo3-base/internal/randtest"
)

// A token that cannot be drawn must not be returned as an empty string. An empty
// token would hash to a fixed value that anyone could present.
func TestGenerateRawToken_FailsWithoutToken(t *testing.T) {
	var tok string
	var err error
	randtest.FailAfter(t, 0, func() { tok, err = GenerateRawToken() })
	if !errors.Is(err, randtest.ErrEntropy) {
		t.Fatalf("err = %v, want the entropy error", err)
	}
	if tok != "" {
		t.Errorf("GenerateRawToken returned %q alongside the error", tok)
	}
}
