package sse_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/sse"
)

var errClientGone = errors.New("client went away")

// unlimited is a budget no test reaches, so only the step under test can fail.
const unlimited = 1 << 30

// flakyWriter is a ResponseWriter for a client that stops accepting data after
// a fixed budget of writes and flushes. Each budget is decremented per call,
// so a test can choose which step of the stream fails.
type flakyWriter struct {
	header  http.Header
	writes  int // Write calls that may still succeed
	flushes int // flushes that may still succeed
}

func (f *flakyWriter) Header() http.Header {
	if f.header == nil {
		f.header = make(http.Header)
	}
	return f.header
}

func (f *flakyWriter) WriteHeader(int) {}

func (f *flakyWriter) Write(b []byte) (int, error) {
	if f.writes <= 0 {
		return 0, errClientGone
	}
	f.writes--
	return len(b), nil
}

// Flush satisfies http.Flusher; FlushError is what http.ResponseController uses,
// and it is the one that reports the failure to the handler.
func (f *flakyWriter) Flush() { _ = f.FlushError() }

func (f *flakyWriter) FlushError() error {
	if f.flushes <= 0 {
		return errClientGone
	}
	f.flushes--
	return nil
}

// serveUntilDone runs the handler and fails the test if it keeps streaming to
// a client that has stopped accepting data.
func serveUntilDone(t *testing.T, h sse.Handler, w *flakyWriter) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler kept streaming after the client stopped accepting data")
	}
}

// Each branch that ends a stream on a write or flush error must return, and
// must not wait for the context. Each case names the step that fails.
func TestHandler_EndsStreamWhenClientStopsAccepting(t *testing.T) {
	cases := []struct {
		name      string
		heartbeat time.Duration
		history   int // messages replayed before the failing step
		writes    int
		flushes   int
	}{
		{"initial flush fails", 0, 0, unlimited, 0},
		{"heartbeat write fails", 5 * time.Millisecond, 0, 0, unlimited},
		{"heartbeat flush fails", 5 * time.Millisecond, 0, unlimited, 1},
		{"event id write fails", 0, 1, 0, unlimited},
		{"event flush fails", 0, 1, unlimited, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := newFakeSource()
			for i := 1; i <= tc.history; i++ {
				src.history = append(src.history, journal.Msg{Seq: uint64(i), Data: []byte("m")})
			}
			h := sse.Handler{Source: src, Heartbeat: tc.heartbeat}
			serveUntilDone(t, h, &flakyWriter{writes: tc.writes, flushes: tc.flushes})
		})
	}
}

// When the journal ends (the source's channel closes), the stream ends
// cleanly, with no error and no wait for the client.
func TestHandler_EndsWhenSourceChannelCloses(t *testing.T) {
	src := newFakeSource()
	close(src.live)
	h := sse.Handler{Source: src}
	serveUntilDone(t, h, &flakyWriter{writes: unlimited, flushes: unlimited})
}
