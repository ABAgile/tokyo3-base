package csrf

import (
	"errors"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/internal/randtest"
)

func TestNewSecret_FailsWithoutSecret(t *testing.T) {
	var s Secret
	var err error
	randtest.FailAfter(t, 0, func() { s, err = NewSecret() })
	if !errors.Is(err, randtest.ErrEntropy) || !strings.Contains(err.Error(), "csrf: secret") {
		t.Fatalf("err = %v, want the entropy error", err)
	}
	if s != "" {
		t.Errorf("NewSecret returned %q alongside the error", s)
	}
}

// Token derives from an existing secret, so the only draw is the mask pad. A
// failed pad must not yield a token.
func TestToken_FailsWithoutPad(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	var tok string
	randtest.FailAfter(t, 0, func() { tok, err = Token(secret, "form") })
	if !errors.Is(err, randtest.ErrEntropy) || !strings.Contains(err.Error(), "csrf: pad") {
		t.Fatalf("err = %v, want the entropy error", err)
	}
	if tok != "" {
		t.Errorf("Token returned %q alongside the error", tok)
	}
}
