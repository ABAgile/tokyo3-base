package journal

import (
	"context"
	"testing"
)

// TestNoop satisfies the Sink interface and exercises both methods. The
// assertion is that they don't error — Noop is by definition the
// always-succeed implementation.
func TestNoop(t *testing.T) {
	var s Sink = Noop{}
	if err := s.Append(context.Background(), []byte("data")); err != nil {
		t.Errorf("Noop.Append: %v", err)
	}
	if err := s.Append(context.Background(), nil); err != nil {
		t.Errorf("Noop.Append(nil): %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Noop.Close: %v", err)
	}
}
