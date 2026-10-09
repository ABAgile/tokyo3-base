package jetstream_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/internal/livetest"
	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/jetstream"
	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file run the Sink and Source against a live JetStream
// server. They skip unless BASE_TEST_NATS_URL is set (see package livetest).

// liveEnv provisions a fresh stream covering a fresh subject family and
// returns the server URL, the stream name, and the subject to publish on.
func liveEnv(t *testing.T) (url, stream, subject string) {
	t.Helper()
	url = livetest.NATSURL(t)
	base := livetest.UniqueName(t, "basetest.")
	stream = livetest.UniqueName(t, "basetest_")
	livetest.CreateJetStreamStream(t, url, stream, base+".>")
	return url, stream, base + ".events"
}

func newSink(t *testing.T, url, subject string) *jetstream.Sink {
	t.Helper()
	sink, err := jetstream.NewSink(jetstream.SinkConfig{URL: url, Subject: subject})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })
	return sink
}

func newSource(t *testing.T, url, stream, subject string) *jetstream.Source {
	t.Helper()
	src, err := jetstream.NewSource(jetstream.SourceConfig{URL: url, StreamName: stream, Subject: subject})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })
	return src
}

// opCtx bounds a single live operation and is cancelled when the test ends.
func opCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func appendAll(t *testing.T, sink *jetstream.Sink, payloads ...string) {
	t.Helper()
	for _, p := range payloads {
		require.NoError(t, sink.Append(opCtx(t), []byte(p)), "Append %q", p)
	}
}

// recvN reads n messages, failing the test if they do not arrive promptly.
func recvN(t *testing.T, ch <-chan journal.Msg, n int) []journal.Msg {
	t.Helper()
	out := make([]journal.Msg, 0, n)
	timeout := time.After(10 * time.Second)
	for len(out) < n {
		select {
		case m, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed after %d of %d messages", len(out), n)
			}
			out = append(out, m)
		case <-timeout:
			t.Fatalf("timed out after %d of %d messages", len(out), n)
		}
	}
	return out
}

func seqs(msgs []journal.Msg) []uint64 {
	out := make([]uint64, len(msgs))
	for i, m := range msgs {
		out[i] = m.Seq
	}
	return out
}

func datas(msgs []journal.Msg) []string {
	out := make([]string, len(msgs))
	for i, m := range msgs {
		out[i] = string(m.Data)
	}
	return out
}

// dialJetStream returns a JetStream handle for inspecting server state.
func dialJetStream(t *testing.T, url string) natsjs.JetStream {
	t.Helper()
	nc, err := nats.Connect(url, nats.Timeout(5*time.Second))
	require.NoError(t, err)
	t.Cleanup(nc.Close)
	js, err := natsjs.New(nc)
	require.NoError(t, err)
	return js
}

// consumerCount reports how many consumers the stream currently has. It
// returns an error rather than failing the test so it can run under Eventually.
func consumerCount(js natsjs.JetStream, stream string) (int, error) {
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

func TestLiveSinkSourceBackfillThenTail(t *testing.T) {
	url, stream, subject := liveEnv(t)
	sink := newSink(t, url, subject)
	src := newSource(t, url, stream, subject)
	appendAll(t, sink, "one", "two", "three")

	ch, err := src.Subscribe(opCtx(t), 10, 0)
	require.NoError(t, err)

	backfill := recvN(t, ch, 3)
	assert.Equal(t, []uint64{1, 2, 3}, seqs(backfill))
	assert.Equal(t, []string{"one", "two", "three"}, datas(backfill))
	for _, m := range backfill {
		assert.False(t, m.Time.IsZero(), "seq %d has no server timestamp", m.Seq)
	}

	appendAll(t, sink, "four")
	live := recvN(t, ch, 1)
	assert.Equal(t, []uint64{4}, seqs(live))
	assert.Equal(t, []string{"four"}, datas(live))
}

func TestLiveSubscribeReplayWindow(t *testing.T) {
	cases := []struct {
		name         string
		replay       int
		wantBackfill []uint64
	}{
		{"tail only", 0, nil},
		{"last two", 2, []uint64{4, 5}},
		{"whole stream", 100, []uint64{1, 2, 3, 4, 5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url, stream, subject := liveEnv(t)
			sink := newSink(t, url, subject)
			src := newSource(t, url, stream, subject)
			appendAll(t, sink, "a", "b", "c", "d", "e")

			ch, err := src.Subscribe(opCtx(t), tc.replay, 0)
			require.NoError(t, err)

			// Publishing after Subscribe returns shows the live tail follows
			// the backfill in order; seq 6 is the first message of the tail.
			appendAll(t, sink, "live")
			got := recvN(t, ch, len(tc.wantBackfill)+1)
			assert.Equal(t, append(slices.Clone(tc.wantBackfill), 6), seqs(got))
		})
	}
}

func TestLiveSubscribeResumeFromSeq(t *testing.T) {
	cases := []struct {
		name         string
		replay       int
		startFromSeq uint64
		want         []uint64
	}{
		// Last-Event-ID style resume: replay from the given sequence onward.
		{"resume inside stream", 0, 3, []uint64{3, 4, 5}},
		// Past the end means the stream was reset; the replay window applies.
		{"resume past end falls back to replay", 2, 99, []uint64{4, 5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url, stream, subject := liveEnv(t)
			sink := newSink(t, url, subject)
			src := newSource(t, url, stream, subject)
			appendAll(t, sink, "a", "b", "c", "d", "e")

			ch, err := src.Subscribe(opCtx(t), tc.replay, tc.startFromSeq)
			require.NoError(t, err)
			assert.Equal(t, tc.want, seqs(recvN(t, ch, len(tc.want))))
		})
	}
}

func TestLiveSubscribeFiltersOtherSubjects(t *testing.T) {
	url, stream, subject := liveEnv(t)
	base := strings.TrimSuffix(subject, ".events")
	events := newSink(t, url, subject)
	other := newSink(t, url, base+".other")
	src := newSource(t, url, stream, subject)

	appendAll(t, other, "ignored")
	appendAll(t, events, "kept")

	ch, err := src.Subscribe(opCtx(t), 10, 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"kept"}, datas(recvN(t, ch, 1)))

	// A sentinel on the filtered subject must be the next message: anything
	// from the other subject would have arrived first.
	appendAll(t, events, "sentinel")
	got := recvN(t, ch, 1)
	assert.Equal(t, []string{"sentinel"}, datas(got))
	assert.Equal(t, []uint64{3}, seqs(got))
}

func TestLiveCancelReleasesEphemeralConsumer(t *testing.T) {
	url, stream, subject := liveEnv(t)
	sink := newSink(t, url, subject)
	src := newSource(t, url, stream, subject)
	js := dialJetStream(t, url)
	appendAll(t, sink, "x")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ch, err := src.Subscribe(ctx, 1, 0)
	require.NoError(t, err)
	recvN(t, ch, 1)

	n, err := consumerCount(js, stream)
	require.NoError(t, err)
	require.Equal(t, 1, n, "consumers while subscribed")

	cancel()
	// The channel closes first; the consumer is deleted just after, so poll.
	timeout := time.After(10 * time.Second)
	for open := true; open; {
		select {
		case _, open = <-ch:
		case <-timeout:
			t.Fatal("channel did not close after cancel")
		}
	}
	assert.Eventually(t, func() bool {
		n, err := consumerCount(js, stream)
		return err == nil && n == 0
	}, 10*time.Second, 50*time.Millisecond, "ephemeral consumer should be deleted after cancel")
}

func TestLiveSourceRetriesStreamLookupAfterMissing(t *testing.T) {
	url := livetest.NATSURL(t)
	base := livetest.UniqueName(t, "basetest.late.")
	stream := livetest.UniqueName(t, "basetest_late_")
	subject := base + ".events"
	src := newSource(t, url, stream, subject)

	// Lookup failures are not memoised, so creating the stream later recovers.
	_, err := src.Subscribe(opCtx(t), 0, 0)
	require.Error(t, err, "Subscribe before the stream exists")

	livetest.CreateJetStreamStream(t, url, stream, base+".>")
	sink := newSink(t, url, subject)
	appendAll(t, sink, "late")

	ch, err := src.Subscribe(opCtx(t), 10, 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"late"}, datas(recvN(t, ch, 1)))
}

func TestLiveSinkFailsClosedWithoutCoveringStream(t *testing.T) {
	url := livetest.NATSURL(t)
	subject := livetest.UniqueName(t, "basetest.unstreamed.") + ".events"
	sink := newSink(t, url, subject)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err := sink.Append(ctx, []byte("must not be silently dropped"))
	assert.ErrorIs(t, err, natsjs.ErrNoStreamResponse, "publish to a subject no stream covers must fail, not be acknowledged")
}

func TestLiveSourceCloseEndsSubscriptions(t *testing.T) {
	url, stream, subject := liveEnv(t)
	src := newSource(t, url, stream, subject)

	ch, err := src.Subscribe(t.Context(), 0, 0)
	require.NoError(t, err)

	require.NoError(t, src.Close())
	timeout := time.After(10 * time.Second)
	for open := true; open; {
		select {
		case _, open = <-ch:
		case <-timeout:
			t.Fatal("subscription channel did not close after Source.Close")
		}
	}
}

func TestLiveAuditSinkAndSourceRoundTrip(t *testing.T) {
	url, stream, subject := liveEnv(t)
	sink, err := jetstream.NewAuditSink[testEntry](jetstream.AuditSinkConfig{
		URL: url, Subject: subject, EnvPrefix: "BASETEST_NATS",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })

	src, err := jetstream.NewAuditSource(jetstream.AuditSourceConfig{
		URL: url, StreamName: stream, Subject: subject, EnvPrefix: "BASETEST_NATS",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	ch, err := src.Subscribe(opCtx(t), 10, 0)
	require.NoError(t, err)

	want := testEntry{ID: "e-1", Action: "issue"}
	require.NoError(t, sink.Append(opCtx(t), want))

	msg := recvN(t, ch, 1)[0]
	var got testEntry
	require.NoError(t, json.Unmarshal(msg.Data, &got))
	assert.Equal(t, want, got)
	assert.Equal(t, uint64(1), msg.Seq)
}
