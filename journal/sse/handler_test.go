package sse_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/sse"
)

// fakeSource is an in-memory journal.Source for testing the SSE handler.
// It serves a fixed history slice on subscribe (filtered by startFromSeq or
// truncated to the last `replay` records) and then tails any messages
// pushed onto the live channel.
type fakeSource struct {
	history []journal.Msg
	live    chan journal.Msg

	// Recorded subscribe arguments — tests inspect these to verify the
	// handler computed the right backfill window from the request.
	gotReplay   int
	gotStartSeq uint64
}

func newFakeSource() *fakeSource {
	return &fakeSource{live: make(chan journal.Msg, 16)}
}

func (f *fakeSource) Subscribe(ctx context.Context, replay int, startFromSeq uint64) (<-chan journal.Msg, error) {
	f.gotReplay = replay
	f.gotStartSeq = startFromSeq

	out := make(chan journal.Msg)
	go func() {
		defer close(out)
		var emit []journal.Msg
		switch {
		case startFromSeq > 0:
			for _, m := range f.history {
				if m.Seq >= startFromSeq {
					emit = append(emit, m)
				}
			}
		case replay > 0:
			n := min(replay, len(f.history))
			emit = f.history[len(f.history)-n:]
		}
		for _, m := range emit {
			select {
			case <-ctx.Done():
				return
			case out <- m:
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case m, ok := <-f.live:
				if !ok {
					return
				}
				select {
				case <-ctx.Done():
					return
				case out <- m:
				}
			}
		}
	}()
	return out, nil
}

func (f *fakeSource) Close() error { return nil }

// sseEvent is one parsed event off the wire. Comment-only lines (heartbeats)
// are reported separately via readEvents' pings counter.
type sseEvent struct {
	id   uint64
	data string
}

// readEvents reads from r until n full events have been seen or r returns
// EOF. Returns the events plus the count of `: ping` heartbeat lines seen.
// Stops eagerly once n events accumulate so a long-running stream doesn't
// block the test.
func readEvents(t *testing.T, r io.Reader, n int) (events []sseEvent, pings int) {
	t.Helper()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var cur sseEvent
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, ": ping"):
			pings++
		case strings.HasPrefix(line, "id: "):
			cur.id, _ = strconv.ParseUint(strings.TrimPrefix(line, "id: "), 10, 64)
		case strings.HasPrefix(line, "data: "):
			cur.data = strings.TrimPrefix(line, "data: ")
		case line == "":
			if cur.id != 0 || cur.data != "" {
				events = append(events, cur)
				cur = sseEvent{}
				if len(events) >= n {
					return
				}
			}
		}
	}
	return
}

// TestHandler_ReplayWindow verifies that with replay=100 and a stream of
// 200 historical messages, the handler emits ids 101..200 — the most-recent
// 100 — in publish order.
func TestHandler_ReplayWindow(t *testing.T) {
	src := newFakeSource()
	for i := 1; i <= 200; i++ {
		src.history = append(src.history, journal.Msg{
			Seq:  uint64(i),
			Time: time.Unix(int64(i), 0).UTC(),
			Data: fmt.Appendf(nil, `{"n":%d}`, i),
		})
	}
	h := sse.Handler{Source: src, Replay: 100, Heartbeat: 0}
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}
	events, _ := readEvents(t, resp.Body, 100)
	if len(events) != 100 {
		t.Fatalf("got %d events, want 100", len(events))
	}
	for i, e := range events {
		wantID := uint64(101 + i)
		if e.id != wantID {
			t.Errorf("event[%d].id = %d, want %d", i, e.id, wantID)
		}
		if e.data != fmt.Sprintf(`{"n":%d}`, wantID) {
			t.Errorf("event[%d].data = %q", i, e.data)
		}
	}
	if src.gotReplay != 100 || src.gotStartSeq != 0 {
		t.Errorf("subscribe args: replay=%d startSeq=%d, want 100,0", src.gotReplay, src.gotStartSeq)
	}
}

// TestHandler_LastEventIDResume verifies that when the client sends
// Last-Event-ID: <n>, the handler subscribes with startFromSeq=n+1 and
// ignores its configured Replay window.
func TestHandler_LastEventIDResume(t *testing.T) {
	src := newFakeSource()
	for i := 1; i <= 50; i++ {
		src.history = append(src.history, journal.Msg{
			Seq: uint64(i), Data: fmt.Appendf(nil, `{"n":%d}`, i),
		})
	}
	h := sse.Handler{Source: src, Replay: 100, Heartbeat: 0}
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	req.Header.Set("Last-Event-ID", "42")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	events, _ := readEvents(t, resp.Body, 8) // expect ids 43..50 = 8 events
	if len(events) != 8 {
		t.Fatalf("got %d events, want 8 (ids 43..50)", len(events))
	}
	if events[0].id != 43 || events[7].id != 50 {
		t.Errorf("range = %d..%d, want 43..50", events[0].id, events[7].id)
	}
	if src.gotStartSeq != 43 {
		t.Errorf("subscribe gotStartSeq = %d, want 43", src.gotStartSeq)
	}
}

// TestHandler_Heartbeat verifies that ": ping" lines fire on idle when
// Heartbeat is set, even with no messages flowing.
func TestHandler_Heartbeat(t *testing.T) {
	src := newFakeSource() // empty history, no live messages
	h := sse.Handler{Source: src, Replay: 0, Heartbeat: 20 * time.Millisecond}
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	_, pings := readEvents(t, resp.Body, 0) // EOF on ctx timeout
	if pings < 3 {
		t.Errorf("got %d ping heartbeats in 200ms at 20ms interval, want >=3", pings)
	}
}

// nonFlushingWriter is the minimal http.ResponseWriter that deliberately
// does NOT implement http.Flusher. httptest.ResponseRecorder is a Flusher
// (no-op Flush) so testing the 500 path requires a hand-rolled writer.
type nonFlushingWriter struct {
	headers http.Header
	code    int
}

func (n *nonFlushingWriter) Header() http.Header {
	if n.headers == nil {
		n.headers = make(http.Header)
	}
	return n.headers
}
func (n *nonFlushingWriter) WriteHeader(c int)           { n.code = c }
func (n *nonFlushingWriter) Write(b []byte) (int, error) { return len(b), nil }

// TestHandler_FlushUnsupported verifies the 500 path when the response
// writer doesn't implement http.Flusher.
func TestHandler_FlushUnsupported(t *testing.T) {
	src := newFakeSource()
	h := sse.Handler{Source: src}
	w := &nonFlushingWriter{}
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(w, req)
	if w.code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.code)
	}
}

// TestHandler_DefaultsApplied verifies that zero Replay/Heartbeat fall
// back to package defaults.
func TestHandler_DefaultsApplied(t *testing.T) {
	src := newFakeSource()
	h := sse.Handler{Source: src} // no Replay, no Heartbeat
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if src.gotReplay != sse.DefaultReplay {
		t.Errorf("gotReplay = %d, want DefaultReplay (%d)", src.gotReplay, sse.DefaultReplay)
	}
}

// TestNoopSource_ClosesOnCancel verifies that the symmetric Noop on the read
// side returns a channel that closes when the context cancels — the minimum
// contract a test or dev environment relies on.
func TestNoopSource_ClosesOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := journal.NoopSource{}.Subscribe(ctx, 100, 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Errorf("got message from NoopSource, want only close")
		}
	case <-time.After(time.Second):
		t.Fatal("channel did not close after ctx cancel")
	}
}
