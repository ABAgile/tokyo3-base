package api

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func softStale(refresher BearerTokenRefresher) *BearerTokenManager {
	// Inside the default 5-minute refresh window but not yet expired.
	return &BearerTokenManager{Token: "old", ExpiresAt: time.Now().Add(3 * time.Minute), Refresher: refresher}
}

func TestBearerToken_SoftWindowFailureServesCurrentToken(t *testing.T) {
	var calls atomic.Int32
	boom := errors.New("idp down")
	tm := softStale(func(context.Context) (string, time.Time, error) {
		calls.Add(1)
		return "", time.Time{}, boom
	})
	var gotErr error
	var gotValid bool
	tm.OnRefreshError = func(err error, valid bool) { gotErr, gotValid = err, valid }

	for range 3 {
		tok, err := tm.GetToken(context.Background())
		if err != nil || tok != "old" {
			t.Fatalf("GetToken = %q, %v; want the still-valid token", tok, err)
		}
	}
	if !errors.Is(gotErr, boom) || !gotValid {
		t.Fatalf("OnRefreshError = (%v, %v), want (idp down, true)", gotErr, gotValid)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("refresher called %d times, want 1 (backoff after failure)", n)
	}
}

func TestBearerToken_ExpiredFailureIsReturnedAndBacksOff(t *testing.T) {
	var calls atomic.Int32
	boom := errors.New("idp down")
	tm := &BearerTokenManager{
		Token: "old", ExpiresAt: time.Now().Add(-time.Minute),
		Refresher: func(context.Context) (string, time.Time, error) {
			calls.Add(1)
			return "", time.Time{}, boom
		},
	}
	if _, err := tm.GetToken(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("first err = %v, want the refresher error", err)
	}
	_, err := tm.GetToken(context.Background())
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "backing off") {
		t.Fatalf("second err = %v, want a backing-off error wrapping the cause", err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("refresher called %d times during backoff, want 1", n)
	}

	// Once the pause has elapsed the refresher runs again and can recover.
	tm.mu.Lock()
	tm.nextAttempt = time.Now().Add(-time.Second)
	tm.Refresher = func(context.Context) (string, time.Time, error) {
		return "new", time.Now().Add(time.Hour), nil
	}
	tm.mu.Unlock()
	if tok, err := tm.GetToken(context.Background()); err != nil || tok != "new" {
		t.Fatalf("after backoff GetToken = %q, %v", tok, err)
	}
}

func TestBearerToken_SoftWindowCallersDoNotWaitForRefresh(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	tm := softStale(func(context.Context) (string, time.Time, error) {
		close(started)
		<-release
		return "new", time.Now().Add(time.Hour), nil
	})

	leader := make(chan string, 1)
	go func() {
		tok, _ := tm.GetToken(context.Background())
		leader <- tok
	}()
	<-started

	done := make(chan string, 1)
	go func() {
		tok, _ := tm.GetToken(context.Background())
		done <- tok
	}()
	select {
	case tok := <-done:
		if tok != "old" {
			t.Fatalf("concurrent caller got %q, want the current token", tok)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a soft-window caller blocked on the in-flight refresh")
	}

	close(release)
	if tok := <-leader; tok != "new" {
		t.Fatalf("leader got %q, want the refreshed token", tok)
	}
}

func TestBearerToken_RefreshSurvivesCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	tm := &BearerTokenManager{
		ExpiresAt: time.Now().Add(-time.Hour),
		Refresher: func(ctx context.Context) (string, time.Time, error) {
			close(started)
			<-release
			if err := ctx.Err(); err != nil {
				return "", time.Time{}, err // the leader's cancellation must not reach us
			}
			return "new", time.Now().Add(time.Hour), nil
		},
	}
	leaderCtx, cancel := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() { _, err := tm.GetToken(leaderCtx); leaderErr <- err }()
	<-started

	waiter := make(chan string, 1)
	go func() { tok, _ := tm.GetToken(context.Background()); waiter <- tok }()
	time.Sleep(20 * time.Millisecond) // let the waiter join the flight

	cancel()
	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader err = %v, want context.Canceled", err)
	}
	close(release)
	if tok := <-waiter; tok != "new" {
		t.Fatalf("waiter got %q after the leader cancelled, want the refreshed token", tok)
	}
}

func TestBearerToken_RefresherMisbehaviourBecomesError(t *testing.T) {
	expired := time.Now().Add(-time.Hour)
	empty := &BearerTokenManager{ExpiresAt: expired, Refresher: func(context.Context) (string, time.Time, error) {
		return "", time.Now().Add(time.Hour), nil
	}}
	if _, err := empty.GetToken(context.Background()); err == nil {
		t.Error("an empty refreshed token must be an error")
	}
	panicky := &BearerTokenManager{ExpiresAt: expired, Refresher: func(context.Context) (string, time.Time, error) {
		panic("kaboom")
	}}
	if _, err := panicky.GetToken(context.Background()); err == nil || !strings.Contains(err.Error(), "kaboom") {
		t.Errorf("a panicking refresher must be reported as an error, got %v", err)
	}
}

// A token whose lifetime is shorter than the refresh buffer must not make
// every call run the Refresher.
func TestBearerToken_ShortLivedTokenIsNotRefreshedPerCall(t *testing.T) {
	var calls atomic.Int32
	tm := &BearerTokenManager{Refresher: func(context.Context) (string, time.Time, error) {
		calls.Add(1)
		return "short", time.Now().Add(3 * time.Minute), nil // < the 5m default buffer
	}}
	for range 5 {
		tok, err := tm.GetToken(context.Background())
		if err != nil || tok != "short" {
			t.Fatalf("GetToken = %q, %v", tok, err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("refresher called %d times for 5 GetToken calls, want 1", n)
	}
}
