package sse_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/sse"
)

// countingSource counts Subscribe calls so tests can prove a refused stream
// never reaches the transport.
type countingSource struct {
	*fakeSource
	subscribes atomic.Int32
}

func (c *countingSource) Subscribe(ctx context.Context, replay int, from uint64) (<-chan journal.Msg, error) {
	c.subscribes.Add(1)
	return c.fakeSource.Subscribe(ctx, replay, from)
}

func clientHeaderKey(r *http.Request) string { return r.Header.Get("X-Client") }

// open starts a stream as client and returns it once the handler has answered.
func open(t *testing.T, url, client string) (*http.Response, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("X-Client", client)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("open stream: %v", err)
	}
	return resp, func() { cancel(); resp.Body.Close() }
}

func TestNewLimits_Validation(t *testing.T) {
	if _, err := sse.NewLimits(sse.LimitsConfig{MaxPerClient: 1}); err == nil {
		t.Error("MaxPerClient without ClientKey must be rejected")
	}
	if _, err := sse.NewLimits(sse.LimitsConfig{MaxStreams: -1}); err == nil {
		t.Error("negative limits must be rejected")
	}
	if _, err := sse.NewLimits(sse.LimitsConfig{}); err != nil {
		t.Errorf("zero config (unlimited) should be valid: %v", err)
	}
}

func TestHandler_PerClientLimitReturns429(t *testing.T) {
	src := &countingSource{fakeSource: newFakeSource()}
	lim, err := sse.NewLimits(sse.LimitsConfig{MaxPerClient: 2, ClientKey: clientHeaderKey, RetryAfter: 7 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(sse.Handler{Source: src, Limits: lim})
	defer srv.Close()

	var closers []context.CancelFunc
	defer func() {
		for _, c := range closers {
			c()
		}
	}()
	for range 2 {
		resp, closeFn := open(t, srv.URL, "alice")
		closers = append(closers, closeFn)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stream within the cap: status %d", resp.StatusCode)
		}
	}

	resp, closeFn := open(t, srv.URL, "alice")
	defer closeFn()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third stream: status %d, want 429", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "7" {
		t.Errorf("Retry-After = %q, want 7", got)
	}
	if ct := resp.Header.Get("Content-Type"); ct == "text/event-stream" {
		t.Error("a refused request must not look like an event stream")
	}
	if n := src.subscribes.Load(); n != 2 {
		t.Errorf("Subscribe called %d times, want 2 (refused stream must not reach the source)", n)
	}

	// Another client is unaffected.
	other, closeOther := open(t, srv.URL, "bob")
	defer closeOther()
	if other.StatusCode != http.StatusOK {
		t.Errorf("other client: status %d, want 200", other.StatusCode)
	}

	// Closing one of alice's streams frees a slot.
	closers[0]()
	deadline := time.Now().Add(2 * time.Second)
	for {
		r, c := open(t, srv.URL, "alice")
		code := r.StatusCode
		if code == http.StatusOK {
			closers = append(closers, c)
			break
		}
		c()
		if time.Now().After(deadline) {
			t.Fatalf("slot not released after a stream closed (last status %d)", code)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHandler_GlobalLimitReturns429(t *testing.T) {
	lim, err := sse.NewLimits(sse.LimitsConfig{MaxStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(sse.Handler{Source: newFakeSource(), Limits: lim})
	defer srv.Close()

	first, closeFirst := open(t, srv.URL, "a")
	defer closeFirst()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first stream: %d", first.StatusCode)
	}
	second, closeSecond := open(t, srv.URL, "b")
	defer closeSecond()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second stream: %d, want 429", second.StatusCode)
	}
	if got := second.Header.Get("Retry-After"); got != "10" {
		t.Errorf("default Retry-After = %q, want 10", got)
	}
}

func TestHandler_LimitReleasedWhenSubscribeFails(t *testing.T) {
	lim, _ := sse.NewLimits(sse.LimitsConfig{MaxStreams: 1})
	h := sse.Handler{Source: rejectedSource{}, Limits: lim}
	for range 3 { // would 429 from the second attempt if the slot leaked
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503 from the failing source", rec.Code)
		}
	}
}
