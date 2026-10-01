package oidc_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/oidc"
)

func TestLazyVerifier_CanceledCallerDoesNotAbortSharedDiscovery(t *testing.T) {
	var hits int32
	entered, release := make(chan struct{}), make(chan struct{})
	var enterOnce, releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	fi := newCountingIssuer(t, &hits, func() bool { enterOnce.Do(func() { close(entered) }); <-release; return false })
	verifier, err := oidc.NewLazyHTTPVerifier(fi.issuer, testAud)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { _, err := verifier.Endpoint(ctx); first <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("discovery did not start")
	}
	second := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := verifier.Endpoint(ctx)
		second <- err
	}()
	cancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled caller remained blocked")
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-second; err != nil {
		t.Fatalf("shared discovery failed: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("discovery fetched %d times", n)
	}
}

func TestLazyVerifier_CanceledContextDoesNotStartDiscovery(t *testing.T) {
	var hits int32
	fi := newCountingIssuer(t, &hits, nil)
	verifier, _ := oidc.NewLazyHTTPVerifier(fi.issuer, testAud)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.Endpoint(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("discovery fetched %d times", n)
	}
}
