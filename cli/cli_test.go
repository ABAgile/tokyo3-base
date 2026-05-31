package cli

import (
	"context"
	"testing"
	"time"
)

func TestSetup(t *testing.T) {
	// No <PREFIX>_NATS_URL / _DEBUG_ADDR in the env ⇒ stdout-only logger,
	// no NATS dial, no diagnostics listener — keeps the test hermetic.
	parent, cancelParent := context.WithCancel(context.Background())
	rt := App{Name: "testd", EnvPrefix: "TESTD_CLI"}.Setup(parent)
	defer rt.Shutdown()

	if rt.Log == nil {
		t.Fatal("Setup returned nil Log")
	}
	if rt.Ctx == nil {
		t.Fatal("Setup returned nil Ctx")
	}
	if rt.Shutdown == nil {
		t.Fatal("Setup returned nil Shutdown")
	}

	select {
	case <-rt.Ctx.Done():
		t.Fatal("Ctx cancelled before parent cancel")
	default:
	}

	// Parent cancellation must propagate to the derived context.
	cancelParent()
	select {
	case <-rt.Ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Ctx did not cancel after parent cancel")
	}
}

func TestShutdownIsSafe(t *testing.T) {
	rt := App{Name: "testd", EnvPrefix: "TESTD_CLI"}.Setup(context.Background())
	rt.Shutdown() // must not panic and must release the signal hook
}
