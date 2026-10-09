package oidcclient

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/internal/randtest"
)

// A failed draw must end the flow with an error. Before this change a failed
// draw crashed the process, and the caller never saw it.
func TestRandomURLSafe_FailsWithoutValue(t *testing.T) {
	var s string
	var err error
	randtest.FailAfter(t, 0, func() { s, err = randomURLSafe(32) })
	if !errors.Is(err, randtest.ErrEntropy) {
		t.Fatalf("err = %v, want the entropy error", err)
	}
	if s != "" {
		t.Errorf("randomURLSafe returned %q alongside the error", s)
	}
}

// RunCodeFlow draws its PKCE verifier before it opens any listener, so a failed
// draw must return an error with no tokens and no network traffic.
func TestRunCodeFlow_FailsWhenEntropyFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var tok *Tokens
	var err error
	randtest.FailAfter(t, 0, func() {
		tok, err = RunCodeFlow(ctx, "https://idp.example", "cli-client", 0, io.Discard)
	})
	if !errors.Is(err, randtest.ErrEntropy) {
		t.Fatalf("err = %v, want the entropy error", err)
	}
	if tok != nil {
		t.Errorf("RunCodeFlow returned tokens alongside the error")
	}
}

// The PKCE verifier is drawn first and succeeds. The CSRF state is drawn second
// and fails, which must still end the flow before any listener opens.
func TestRunCodeFlow_FailsWhenStateCannotBeDrawn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var tok *Tokens
	var err error
	randtest.FailAfter(t, 1, func() {
		tok, err = RunCodeFlow(ctx, "https://idp.example", "cli-client", 0, io.Discard)
	})
	if !errors.Is(err, randtest.ErrEntropy) {
		t.Fatalf("err = %v, want the entropy error from the state draw", err)
	}
	if tok != nil {
		t.Errorf("RunCodeFlow returned tokens alongside the error")
	}
}
