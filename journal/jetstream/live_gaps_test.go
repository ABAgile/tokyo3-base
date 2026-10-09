package jetstream_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/jetstream"
	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
)

// These live tests cover subscription and connection paths that need a real
// server: a stream deleted under a running subscription, and closing a
// connection. They skip unless BASE_TEST_NATS_URL is set.

// logBuf is a goroutine-safe log sink: NATS callbacks log from their own
// goroutines.
type logBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func deleteStream(t *testing.T, url, name string) {
	t.Helper()
	nc, err := nats.Connect(url, nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := natsjs.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := js.DeleteStream(ctx, name); err != nil {
		t.Fatalf("delete stream %s: %v", name, err)
	}
}

// drainUntilClosed reads and discards until ch closes, failing after ten
// seconds.
func drainUntilClosed(t *testing.T, ch <-chan journal.Msg) {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case _, open := <-ch:
			if !open {
				return
			}
		case <-timeout:
			t.Fatal("subscription channel did not close")
		}
	}
}

// Deleting the stream under a live subscription must end it: the channel
// closes, and the cause is logged, so the closed channel does not look like a
// clean end of stream.
func TestLiveSubscriptionEndsWhenStreamIsDeleted(t *testing.T) {
	url, stream, subject := liveEnv(t)
	sink := newSink(t, url, subject)
	logs := &logBuf{}
	src, err := jetstream.NewSource(jetstream.SourceConfig{
		URL: url, StreamName: stream, Subject: subject,
		Log: slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = src.Close() })
	appendAll(t, sink, "before")

	ch, err := src.Subscribe(t.Context(), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	recvN(t, ch, 1)

	deleteStream(t, url, stream)
	drainUntilClosed(t, ch)
	if !strings.Contains(logs.String(), "jetstream subscription ended") {
		t.Errorf("stream deletion not logged: %q", logs.String())
	}
}

// Once the stream lookup is memoised, a later Subscribe still asks the server
// for the stream's info. After a deletion that must return an error, not
// create a consumer on a stream that no longer exists.
func TestLiveSubscribeAfterStreamDeletionErrors(t *testing.T) {
	url, stream, subject := liveEnv(t)
	src := newSource(t, url, stream, subject)

	ch, err := src.Subscribe(opCtx(t), 0, 0)
	if err != nil {
		t.Fatalf("first Subscribe: %v", err)
	}
	_ = ch

	deleteStream(t, url, stream)
	if _, err := src.Subscribe(opCtx(t), 0, 0); err == nil {
		t.Fatal("Subscribe after the stream was deleted returned nil error")
	}
}

// If the caller cancels while nobody is reading, the delivery goroutine must
// still exit, so the ephemeral consumer is deleted. The channel is never read
// here: reading would unblock the goroutine's pending send and hide a stuck
// goroutine.
func TestLiveCancelWithSlowReaderReleasesConsumer(t *testing.T) {
	url, stream, subject := liveEnv(t)
	sink := newSink(t, url, subject)
	src := newSource(t, url, stream, subject)
	js := dialJetStream(t, url)
	appendAll(t, sink, "a", "b", "c", "d", "e")

	ctx, cancel := context.WithCancel(t.Context())
	if _, err := src.Subscribe(ctx, 5, 0); err != nil {
		t.Fatal(err)
	}
	// Let the goroutine park on its first send before cancelling.
	time.Sleep(50 * time.Millisecond)
	cancel()

	assert.Eventually(t, func() bool {
		n, err := consumerCount(js, stream)
		return err == nil && n == 0
	}, 10*time.Second, 50*time.Millisecond, "consumer should be deleted even with no reader")
}

// Closing a sink drains its connection, and the lifecycle hook must log the
// close under the sink's face name.
func TestLiveSinkCloseLogsConnectionClosed(t *testing.T) {
	url, _, subject := liveEnv(t)
	logs := &logBuf{}
	sink, err := jetstream.NewSink(jetstream.SinkConfig{
		URL: url, Subject: subject,
		Log: slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logs.String(), "nats connection closed") {
		if time.Now().After(deadline) {
			t.Fatalf("connection close not logged: %q", logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "jetstream-sink") {
		t.Errorf("close log does not name the sink face: %q", logs.String())
	}
}
