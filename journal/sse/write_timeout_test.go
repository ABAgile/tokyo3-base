package sse_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/sse"
)

// floodSource emits large messages until its context ends.
type floodSource struct{}

func (floodSource) Subscribe(ctx context.Context, _ int, _ uint64) (<-chan journal.Msg, error) {
	out := make(chan journal.Msg)
	go func() {
		defer close(out)
		big := bytes.Repeat([]byte("x"), 256<<10)
		for seq := uint64(1); ; seq++ {
			select {
			case <-ctx.Done():
				return
			case out <- journal.Msg{Seq: seq, Data: big}:
			}
		}
	}()
	return out, nil
}
func (floodSource) Close() error { return nil }

// A client that connects and never reads must not hold its stream open
// forever: the per-write deadline ends it.
func TestHandler_StalledClientIsDropped(t *testing.T) {
	finished := make(chan struct{})
	h := sse.Handler{Source: floodSource{}, WriteTimeout: 200 * time.Millisecond}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(1024)
	}
	if _, err := conn.Write([]byte("GET /events HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("stream to a client that never reads was not dropped")
	}
}

func TestHandler_UsesConfiguredLogger(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	rec := httptest.NewRecorder()
	sse.Handler{Source: rejectedSource{}, Log: log}.ServeHTTP(rec, httptest.NewRequest("GET", "/events", nil))
	if !strings.Contains(buf.String(), "journal SSE subscription failed") {
		t.Fatalf("configured logger got %q", buf.String())
	}
}

// A stream that ends normally after its last write deadline has expired must
// still terminate cleanly, so the client sees a complete response rather than
// a truncated one.
func TestHandler_CleanEndAfterDeadlineExpired(t *testing.T) {
	src := newFakeSource()
	done := make(chan struct{})
	h := sse.Handler{Source: src, Replay: 1, WriteTimeout: 50 * time.Millisecond, Done: done}
	src.history = []journal.Msg{{Seq: 1, Data: []byte("hello")}}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // the last write deadline is now in the past
	close(done)
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("stream ended uncleanly: %v", err)
	}
}
