package run_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/run"
)

func TestGroup_FirstExitCancelsRest(t *testing.T) {
	var bStopped atomic.Bool
	// a returns quickly with a real error; b blocks on ctx and must be
	// cancelled as a result.
	a := func(context.Context) error { return errors.New("a failed") }
	b := func(ctx context.Context) error {
		<-ctx.Done()
		bStopped.Store(true)
		return ctx.Err()
	}

	err := run.Group(context.Background(), a, b)
	if err == nil || err.Error() != "a failed" {
		t.Fatalf("err = %v, want \"a failed\"", err)
	}
	if !bStopped.Load() {
		t.Error("b was not cancelled by a's exit")
	}
}

func TestGroup_CleanExitReturnsNil(t *testing.T) {
	// a exits cleanly first; b is cancelled and returns context.Canceled,
	// which Group must NOT surface as an error.
	a := func(context.Context) error { return nil }
	b := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	if err := run.Group(context.Background(), a, b); err != nil {
		t.Fatalf("clean first exit should yield nil, got %v", err)
	}
}

func TestGroup_ParentCancelStopsAll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	block := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	done := make(chan error, 1)
	go func() { done <- run.Group(ctx, block, block) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("parent-cancel teardown should be nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Group did not return after parent cancel")
	}
}

func TestGroup_Empty(t *testing.T) {
	if err := run.Group(context.Background()); err != nil {
		t.Fatalf("empty group = %v, want nil", err)
	}
}

func TestHTTPServer_ShutsDownOnCancel(t *testing.T) {
	srv := &http.Server{Handler: http.NewServeMux()}
	// Bind explicitly so the component owns a real listener lifecycle.
	srv.Addr = "127.0.0.1:0"
	comp := run.HTTPServer(srv, time.Second, false)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- comp(ctx) }()

	// Give ListenAndServe a beat to bind, then cancel for graceful shutdown.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTPServer did not return after cancel")
	}
}
