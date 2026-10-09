package session

import (
	"errors"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/internal/randtest"
)

// NewSession without a CSRF secret would hand out a session whose CSRF tokens
// are keyed by an empty secret. It must fail instead.
func TestNewSession_FailsWithoutCSRFSecret(t *testing.T) {
	m := testManager(t, nil)
	var sess Session
	var err error
	randtest.FailAfter(t, 0, func() { sess, err = m.NewSession() })
	if !errors.Is(err, randtest.ErrEntropy) || !strings.Contains(err.Error(), "session: csrf secret") {
		t.Fatalf("err = %v, want the entropy error", err)
	}
	if sess.CSRFSecret != "" || sess.Subject != "" || !sess.Expiry.IsZero() {
		t.Errorf("NewSession returned a partial session alongside the error: %+v", sess)
	}
}
