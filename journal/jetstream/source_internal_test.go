package jetstream

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/require"
)

// lookupJS stands in for the JetStream client. ensureStream calls only Stream,
// so the embedded nil interface is never reached. The first Stream call waits
// for release or its own ctx; later calls succeed at once.
type lookupJS struct {
	jetstream.JetStream
	calls   atomic.Int32
	release chan struct{}
}

type stubStream struct{ jetstream.Stream }

func (f *lookupJS) Stream(ctx context.Context, _ string) (jetstream.Stream, error) {
	if f.calls.Add(1) == 1 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.release:
		}
	}
	return stubStream{}, nil
}

// A caller that waits behind an in-flight stream lookup must give up at its
// own deadline, not when that lookup ends.
func TestEnsureStreamWaiterHonoursItsOwnContext(t *testing.T) {
	js := &lookupJS{release: make(chan struct{})}
	s := &Source{js: js, streamName: "events"}

	leaderDone := make(chan error, 1)
	go func() {
		_, err := s.ensureStream(t.Context())
		leaderDone <- err
	}()
	require.Eventually(t, func() bool { return js.calls.Load() == 1 }, 2*time.Second, time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	waiterDone := make(chan error, 1)
	go func() {
		_, err := s.ensureStream(ctx)
		waiterDone <- err
	}()
	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("waiter error = %v, want DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter stayed blocked behind the in-flight lookup past its deadline")
	}

	close(js.release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader lookup: %v", err)
	}
	if n := js.calls.Load(); n != 1 {
		t.Fatalf("Stream called %d times, want 1", n)
	}
}

// When the caller running the lookup gives up, a waiter with a live context
// must not inherit that failure. It runs the lookup itself, and the result is
// memoised.
func TestEnsureStreamWaiterRetriesAfterLeaderFails(t *testing.T) {
	js := &lookupJS{release: make(chan struct{})}
	s := &Source{js: js, streamName: "events"}

	leaderCtx, cancelLeader := context.WithCancel(t.Context())
	defer cancelLeader()
	leaderDone := make(chan error, 1)
	go func() {
		_, err := s.ensureStream(leaderCtx)
		leaderDone <- err
	}()
	require.Eventually(t, func() bool { return js.calls.Load() == 1 }, 2*time.Second, time.Millisecond)

	waiterDone := make(chan error, 1)
	go func() {
		_, err := s.ensureStream(t.Context())
		waiterDone <- err
	}()
	cancelLeader()

	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want Canceled", err)
	}
	select {
	case err := <-waiterDone:
		if err != nil {
			t.Fatalf("waiter inherited the leader's failure: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter never finished after the leader failed")
	}
	if n := js.calls.Load(); n != 2 {
		t.Fatalf("Stream called %d times, want 2", n)
	}
	if _, err := s.ensureStream(t.Context()); err != nil {
		t.Fatalf("memoised lookup: %v", err)
	}
	if n := js.calls.Load(); n != 2 {
		t.Fatalf("memoised lookup re-ran Stream: %d calls, want 2", n)
	}
}

// panicJS panics on its first Stream call and succeeds afterwards.
type panicJS struct {
	jetstream.JetStream
	calls atomic.Int32
}

func (f *panicJS) Stream(context.Context, string) (jetstream.Stream, error) {
	if f.calls.Add(1) == 1 {
		panic("lookup failed")
	}
	return stubStream{}, nil
}

// A panicking lookup must not leave later callers blocked behind it. The panic
// reaches its own caller, and the next caller runs the lookup again.
func TestEnsureStreamAfterPanickingLookup(t *testing.T) {
	s := &Source{js: &panicJS{}, streamName: "events"}
	require.Panics(t, func() { _, _ = s.ensureStream(t.Context()) })

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := s.ensureStream(ctx); err != nil {
		t.Fatalf("lookup after a panic: %v", err)
	}
}

// endlessMsgs is an iterator that yields a message on every Next and records
// when it is stopped.
type endlessMsgs struct {
	jetstream.MessagesContext
	stopped atomic.Bool
}

func (m *endlessMsgs) Next(...jetstream.NextOpt) (jetstream.Msg, error) {
	if m.stopped.Load() {
		return nil, jetstream.ErrMsgIteratorClosed
	}
	return stubMsg{}, nil
}

func (m *endlessMsgs) Stop() { m.stopped.Store(true) }

type stubMsg struct{ jetstream.Msg }

func (stubMsg) Metadata() (*jetstream.MsgMetadata, error) {
	return &jetstream.MsgMetadata{Sequence: jetstream.SequencePair{Stream: 1}}, nil
}

func (stubMsg) Data() []byte { return []byte("payload") }

type stubConsumer struct {
	jetstream.Consumer
	msgs *endlessMsgs
}

func (c stubConsumer) CachedInfo() *jetstream.ConsumerInfo {
	return &jetstream.ConsumerInfo{Name: "ephemeral"}
}

func (c stubConsumer) Messages(...jetstream.PullMessagesOpt) (jetstream.MessagesContext, error) {
	return c.msgs, nil
}

// subStream serves one ephemeral consumer over an endless iterator and records
// when the consumer is deleted, which happens only when the delivery goroutine
// returns.
type subStream struct {
	jetstream.Stream
	msgs    *endlessMsgs
	deleted atomic.Bool
}

func (s *subStream) Info(context.Context, ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
	return &jetstream.StreamInfo{State: jetstream.StreamState{FirstSeq: 1, LastSeq: 3}}, nil
}

func (s *subStream) CreateOrUpdateConsumer(context.Context, jetstream.ConsumerConfig) (jetstream.Consumer, error) {
	return stubConsumer{msgs: s.msgs}, nil
}

func (s *subStream) DeleteConsumer(context.Context, string) error {
	s.deleted.Store(true)
	return nil
}

type subJS struct {
	jetstream.JetStream
	stream *subStream
}

func (j subJS) Stream(context.Context, string) (jetstream.Stream, error) { return j.stream, nil }

// Close must end a subscription whose delivery goroutine is parked on a send
// because nobody reads. Draining the connection does not release that send,
// so the test checks that the goroutine exits without any read from ch.
func TestSourceCloseEndsSubscriptionWithoutReader(t *testing.T) {
	stream := &subStream{msgs: &endlessMsgs{}}
	// Close drains the connection, so it needs a real one. It never connects,
	// which keeps the test off the network.
	nc, err := nats.Connect("nats://127.0.0.1:1", nats.RetryOnFailedConnect(true))
	require.NoError(t, err)
	s := &Source{
		nc:                nc,
		js:                subJS{stream: stream},
		streamName:        "events",
		subject:           "events.x",
		inactiveThreshold: time.Minute,
		closing:           make(chan struct{}),
	}

	if _, err := s.Subscribe(t.Context(), 0, 0); err != nil {
		t.Fatal(err)
	}
	// Let the delivery goroutine park on its first send before closing.
	time.Sleep(20 * time.Millisecond)
	_ = s.Close()

	require.Eventually(t, func() bool {
		return stream.msgs.stopped.Load() && stream.deleted.Load()
	}, 2*time.Second, time.Millisecond, "subscription still running after Close with no reader")
}
