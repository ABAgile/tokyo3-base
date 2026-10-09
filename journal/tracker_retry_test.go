package journal_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"
)

var errSubscribe = errors.New("broker unavailable")

// syncLog is a goroutine-safe log sink: the tracker logs from its Run goroutine
// while the test polls.
type syncLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// flakySubscribeSource fails the first failures Subscribe calls, then serves a
// single message and keeps the stream open until its context ends.
type flakySubscribeSource struct {
	failures int
	calls    int
	msg      journal.Msg
}

func (f *flakySubscribeSource) Subscribe(ctx context.Context, _ int, _ uint64) (<-chan journal.Msg, error) {
	f.calls++
	if f.calls <= f.failures {
		return nil, errSubscribe
	}
	ch := make(chan journal.Msg, 1)
	ch <- f.msg
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, nil
}

func (f *flakySubscribeSource) Close() error { return nil }

// Without a resubscribe wait, a failed Subscribe is terminal: Run returns the
// error rather than retrying.
func TestTracker_SubscribeFailureWithoutResubscribeEndsRun(t *testing.T) {
	src := &flakySubscribeSource{failures: 1 << 30}
	tr, err := journal.NewTracker(journal.TrackerConfig[event]{
		Source: src, Decode: decodeEvent, Max: 10, Log: discard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The deadline turns a retry loop into a failure instead of a hang.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tr.Run(ctx); !errors.Is(err, errSubscribe) {
		t.Fatalf("Run = %v, want the subscribe error", err)
	}
}

// With a resubscribe wait, failed subscriptions are retried until the source
// recovers. Each failure is logged, and the recovered stream is ingested.
func TestTracker_RetriesSubscribeFailuresUntilSourceRecovers(t *testing.T) {
	logs := &syncLog{}
	src := &flakySubscribeSource{failures: 2, msg: jmsg(t, 1, "a", time.Now())}
	tr, err := journal.NewTracker(journal.TrackerConfig[event]{
		Source: src, Decode: decodeEvent, Max: 10,
		ResubscribeWait: time.Millisecond,
		Log:             slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for len(tr.Snapshot()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("event never ingested after the source recovered")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if src.calls != 3 {
		t.Errorf("Subscribe calls = %d, want 3 (two failures, then success)", src.calls)
	}
	if n := strings.Count(logs.String(), "subscribe failed; retrying"); n != 2 {
		t.Errorf("retry warnings = %d, want one per failed subscribe (2):\n%s", n, logs.String())
	}
}

// A tracker built without a logger reports through slog's default logger, so
// retries are still visible to the operator.
func TestNewTracker_NilLogUsesDefaultLogger(t *testing.T) {
	logs := &syncLog{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	src := &flakySubscribeSource{failures: 1, msg: jmsg(t, 1, "a", time.Now())}
	tr, err := journal.NewTracker(journal.TrackerConfig[event]{
		Source: src, Decode: decodeEvent, ResubscribeWait: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "subscribe failed; retrying") {
		if time.Now().After(deadline) {
			t.Fatalf("retry warning did not reach the default logger:\n%s", logs.String())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-errCh
}
