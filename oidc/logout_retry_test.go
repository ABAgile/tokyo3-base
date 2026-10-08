package oidc

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestBackchannelLogout_FailedOperationsCanRetry(t *testing.T) {
	for _, kind := range []string{"session", "user", "audit"} {
		t.Run(kind, func(t *testing.T) {
			rev := &fakeRevoker{userOK: true}
			claims := &LogoutClaims{SessionID: "s", JTI: "j"}
			h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{Verifier: &fakeLogoutVerifier{claims: claims}, Revoker: rev})
			switch kind {
			case "session":
				rev.sessionErr = errors.New("failed")
			case "user":
				claims.SessionID = ""
				claims.Subject = "u"
				rev.userErr = errors.New("failed")
			case "audit":
				h.cfg.OnRevoked = func(*http.Request, *LogoutClaims, string, string, int64) error { return errors.New("failed") }
			}
			if got := postLogout(h, "token").Code; got != 500 {
				t.Fatalf("first status=%d", got)
			}
			rev.sessionErr = nil
			rev.userErr = nil
			h.cfg.OnRevoked = nil
			if got := postLogout(h, "token").Code; got != 200 {
				t.Fatalf("retry status=%d", got)
			}
			if got := postLogout(h, "token").Code; got != 400 {
				t.Fatalf("completed replay status=%d", got)
			}
		})
	}
}

type blockingRevoker struct{ entered, release chan struct{} }

func (r *blockingRevoker) RevokeSession(context.Context, string) (int64, error) {
	close(r.entered)
	<-r.release
	return 1, nil
}
func (*blockingRevoker) RevokeUser(context.Context, string, string) (int64, string, bool, error) {
	return 0, "", false, nil
}
func TestBackchannelLogout_RejectsConcurrentReplay(t *testing.T) {
	rev := &blockingRevoker{make(chan struct{}), make(chan struct{})}
	h, _ := NewBackchannelLogoutHandler(BackchannelLogoutConfig{Verifier: &fakeLogoutVerifier{claims: &LogoutClaims{SessionID: "s", JTI: "j"}}, Revoker: rev})
	done := make(chan int, 1)
	go func() { done <- postLogout(h, "token").Code }()
	<-rev.entered
	if got := postLogout(h, "token").Code; got != 400 {
		t.Errorf("concurrent replay=%d", got)
	}
	close(rev.release)
	if got := <-done; got != 200 {
		t.Fatalf("first status=%d", got)
	}
}
func TestLogoutJTICache_PendingDoesNotExpire(t *testing.T) {
	c := newLogoutJTICache(time.Minute)
	now := time.Now()
	if !c.accept("j", now) || c.accept("j", now.Add(time.Hour)) {
		t.Fatal("pending reservation expired")
	}
	c.finish("j", false, now.Add(time.Hour))
	if !c.accept("j", now.Add(time.Hour)) {
		t.Fatal("failure did not release reservation")
	}
	c.finish("j", true, now.Add(time.Hour))
	if c.accept("j", now.Add(time.Hour+30*time.Second)) {
		t.Fatal("successful replay accepted")
	}
	if !c.accept("j", now.Add(time.Hour+2*time.Minute)) {
		t.Fatal("completed reservation did not expire")
	}
}

// An expired entry that has not been swept yet must not count as a replay.
func TestLogoutJTICache_ExpiredUnsweptIsNotReplay(t *testing.T) {
	c := newLogoutJTICache(10 * time.Second)
	now := time.Now()
	c.accept("a", now) // first call sweeps; later calls within jtiSweepInterval do not
	c.finish("a", true, now)
	if !c.accept("b", now.Add(time.Second)) {
		t.Fatal("accept b")
	}
	if !c.accept("a", now.Add(30*time.Second)) {
		t.Fatal("expired, unswept jti was rejected as a replay")
	}
}
