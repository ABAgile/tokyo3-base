package sse_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/internal/livetest"
	"github.com/abagile/tokyo3-base/journal/jetstream"
	"github.com/abagile/tokyo3-base/journal/sse"
	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
)

// The tests in this file stream a real JetStream source through the SSE
// handler. They skip unless BASE_TEST_NATS_URL is set (see package livetest).

type liveSSE struct {
	url, stream string
	sink        *jetstream.Sink
	src         *jetstream.Source
}

// newLiveSSE provisions a stream and publishes history messages with seq 1..n
// and data "m<seq>". The Sink and Source are closed on cleanup.
func newLiveSSE(t *testing.T, history int) liveSSE {
	t.Helper()
	url := livetest.NATSURL(t)
	base := livetest.UniqueName(t, "basetest.sse.")
	stream := livetest.UniqueName(t, "basetest_sse_")
	subject := base + ".events"
	livetest.CreateJetStreamStream(t, url, stream, base+".>")

	sink, err := jetstream.NewSink(jetstream.SinkConfig{URL: url, Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	for i := 1; i <= history; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		err := sink.Append(ctx, fmt.Appendf(nil, "m%d", i))
		cancel()
		if err != nil {
			t.Fatalf("append m%d: %v", i, err)
		}
	}

	src, err := jetstream.NewSource(jetstream.SourceConfig{URL: url, StreamName: stream, Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = src.Close() })
	return liveSSE{url: url, stream: stream, sink: sink, src: src}
}

// serve starts the SSE handler over env's source and returns its URL.
func (e liveSSE) serve(t *testing.T, replay int) string {
	t.Helper()
	h := sse.Handler{
		Source:    e.src,
		Replay:    replay,
		Heartbeat: time.Hour,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// get opens an event stream, optionally resuming from lastEventID.
func get(t *testing.T, ctx context.Context, url, lastEventID string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// consumerCounter returns a function reporting the stream's consumer count.
func consumerCounter(t *testing.T, url, stream string) func() (int, error) {
	t.Helper()
	nc, err := nats.Connect(url, nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := natsjs.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	return func() (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := js.Stream(ctx, stream)
		if err != nil {
			return 0, err
		}
		info, err := s.Info(ctx)
		if err != nil {
			return 0, err
		}
		return info.State.Consumers, nil
	}
}

// eventually polls cond until it holds, failing after ten seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A new client gets the replay window, then messages published afterwards.
// The live message is published only once the JetStream consumer exists, so
// it cannot race the subscription.
func TestLiveSSE_BackfillThenLiveTail(t *testing.T) {
	env := newLiveSSE(t, 5)
	url := env.serve(t, 2)
	count := consumerCounter(t, env.url, env.stream)

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	resp := get(t, ctx, url, "")
	eventually(t, "the JetStream consumer to exist", func() bool {
		n, err := count()
		return err == nil && n == 1
	})

	pubCtx, pubCancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer pubCancel()
	if err := env.sink.Append(pubCtx, []byte("m6")); err != nil {
		t.Fatal(err)
	}

	events, _ := readEvents(t, resp.Body, 3)
	want := []struct {
		id   uint64
		data string
	}{{4, "m4"}, {5, "m5"}, {6, "m6"}}
	if len(events) != len(want) {
		t.Fatalf("got %d events, want %d: %+v", len(events), len(want), events)
	}
	for i, w := range want {
		if events[i].id != w.id || events[i].data != w.data {
			t.Errorf("event %d = (%d, %q), want (%d, %q)", i, events[i].id, events[i].data, w.id, w.data)
		}
	}
}

// Last-Event-ID resumes from the event after it and ignores the replay
// window. With Replay 1 the window alone would give only the last event.
func TestLiveSSE_LastEventIDResumesFromRealStream(t *testing.T) {
	env := newLiveSSE(t, 5)
	url := env.serve(t, 1)

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	resp := get(t, ctx, url, "1")
	events, _ := readEvents(t, resp.Body, 4)
	if len(events) != 4 || events[0].id != 2 || events[3].id != 5 {
		t.Fatalf("resume from 1 gave %+v, want ids 2..5", events)
	}
}

// A Last-Event-ID beyond the stream end means the stream was reset, so the
// handler falls back to the replay window.
func TestLiveSSE_ResumePastEndFallsBackToReplayWindow(t *testing.T) {
	env := newLiveSSE(t, 5)
	url := env.serve(t, 2)

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	resp := get(t, ctx, url, "99")
	events, _ := readEvents(t, resp.Body, 2)
	if len(events) != 2 || events[0].id != 4 || events[1].id != 5 {
		t.Fatalf("reset resume gave %+v, want the replay window ids 4..5", events)
	}
}

// When the client goes away, the handler must end the subscription and the
// JetStream consumer must be deleted. Otherwise each reconnect would leave a
// consumer behind until its inactivity threshold expires.
func TestLiveSSE_ClientDisconnectReleasesConsumer(t *testing.T) {
	env := newLiveSSE(t, 1)
	url := env.serve(t, 1)
	count := consumerCounter(t, env.url, env.stream)

	ctx, cancel := context.WithCancel(t.Context())
	resp := get(t, ctx, url, "")
	if events, _ := readEvents(t, resp.Body, 1); len(events) != 1 {
		t.Fatalf("got %d events before disconnect, want 1", len(events))
	}
	eventually(t, "the JetStream consumer to exist", func() bool {
		n, err := count()
		return err == nil && n == 1
	})

	cancel()
	resp.Body.Close()
	eventually(t, "the JetStream consumer to be deleted after disconnect", func() bool {
		n, err := count()
		return err == nil && n == 0
	})
}
