package sse

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestLimits_AcquireReleaseBookkeeping(t *testing.T) {
	l, err := NewLimits(LimitsConfig{MaxStreams: 3, MaxPerClient: 2, ClientKey: func(r *http.Request) string { return r.Header.Get("K") }})
	if err != nil {
		t.Fatal(err)
	}
	req := func(k string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("K", k)
		return r
	}

	a1, _, ok1 := l.acquire(req("a"))
	a2, _, ok2 := l.acquire(req("a"))
	if !ok1 || !ok2 {
		t.Fatal("acquires within the caps failed")
	}
	if _, scope, ok := l.acquire(req("a")); ok || scope != scopeClient {
		t.Fatalf("third for one client: ok=%v scope=%q, want refused by the client cap", ok, scope)
	}
	b1, _, ok := l.acquire(req("b"))
	if !ok {
		t.Fatal("other client refused below the global cap")
	}
	if _, scope, ok := l.acquire(req("c")); ok || scope != scopeGlobal {
		t.Fatalf("over the global cap: ok=%v scope=%q", ok, scope)
	}

	a1()
	a1() // idempotent: a double release must not free a second slot
	if l.total != 2 || l.perClient["a"] != 1 {
		t.Fatalf("after release: total=%d a=%d, want 2 and 1", l.total, l.perClient["a"])
	}
	a2()
	b1()
	if l.total != 0 || len(l.perClient) != 0 {
		t.Fatalf("limiter did not drain: total=%d clients=%d", l.total, len(l.perClient))
	}
}

func TestLimits_NilIsUnlimited(t *testing.T) {
	var l *Limits
	release, _, ok := l.acquire(httptest.NewRequest(http.MethodGet, "/", nil))
	if !ok {
		t.Fatal("nil Limits must allow every stream")
	}
	release()
}

func TestLimits_ConcurrentNeverExceedsCap(t *testing.T) {
	l, _ := NewLimits(LimitsConfig{MaxStreams: 5, MaxPerClient: 3, ClientKey: func(*http.Request) string { return "x" }})
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		held    int
		maxHeld int
	)
	for range 64 {
		wg.Go(func() {
			for range 200 {
				release, _, ok := l.acquire(httptest.NewRequest(http.MethodGet, "/", nil))
				if !ok {
					continue
				}
				mu.Lock()
				held++
				maxHeld = max(maxHeld, held)
				mu.Unlock()
				mu.Lock()
				held--
				mu.Unlock()
				release()
			}
		})
	}
	wg.Wait()
	if maxHeld > 3 {
		t.Fatalf("held %d slots at once, cap is 3", maxHeld)
	}
	if l.total != 0 || len(l.perClient) != 0 {
		t.Fatalf("limiter leaked: total=%d clients=%d", l.total, len(l.perClient))
	}
}

func TestLimits_RejectRetryAfterAtLeastOneSecond(t *testing.T) {
	l, err := NewLimits(LimitsConfig{MaxStreams: 1, RetryAfter: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	l.reject(rec)
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
}
