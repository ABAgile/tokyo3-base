package jetstream

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
)

// ── Sink (write face) ────────────────────────────────────────────────────────

// TestNewSink_MissingURL covers the fast-fail config validation: empty URL
// must error before any network attempt.
func TestNewSink_MissingURL(t *testing.T) {
	if _, err := NewSink(SinkConfig{Subject: "events"}); err == nil {
		t.Error("expected error for missing URL, got nil")
	}
}

// TestNewSink_MissingSubject covers the second config check: a URL without
// a subject must error before reaching nats.Connect.
func TestNewSink_MissingSubject(t *testing.T) {
	if _, err := NewSink(SinkConfig{URL: "nats://localhost:4222"}); err == nil {
		t.Error("expected error for missing Subject, got nil")
	}
}

// TestNewSink_NoErrOnUnreachable proves the lazy-connect contract:
// pointing at a port nothing listens on must not return an error.
// The connection retries in the background; publish-time failures
// surface there.
func TestNewSink_NoErrOnUnreachable(t *testing.T) {
	sink, err := NewSink(SinkConfig{
		URL:     "nats://127.0.0.1:1",
		Subject: "events",
	})
	if err != nil {
		t.Fatalf("NewSink on unreachable URL: %v, want nil", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
}

// ── Source (read face) ───────────────────────────────────────────────────────

// TestNewSource_NoErrOnUnreachable proves the lazy-connect contract
// symmetrically with the Sink: construction must not error when the
// broker is unreachable. Stream lookup is deferred to first Subscribe.
func TestNewSource_NoErrOnUnreachable(t *testing.T) {
	src, err := NewSource(SourceConfig{
		URL:        "nats://127.0.0.1:1",
		StreamName: "any",
		Subject:    "events",
	})
	if err != nil {
		t.Fatalf("NewSource on unreachable URL: %v, want nil", err)
	}
	t.Cleanup(func() { _ = src.Close() })
}

// TestNewSource_MissingFields covers the SourceConfig fast-fail checks
// symmetrically with the SinkConfig tests above.
func TestNewSource_MissingFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  SourceConfig
	}{
		{"missing URL", SourceConfig{StreamName: "s", Subject: "events"}},
		{"missing StreamName", SourceConfig{URL: "nats://localhost:4222", Subject: "events"}},
		{"missing Subject", SourceConfig{URL: "nats://localhost:4222", StreamName: "s"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSource(tc.cfg); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestPickDeliverPolicy locks the start-policy decision tree without needing
// a live JetStream server. The four branches are mutually exclusive:
//
//   - resume (Last-Event-ID): startFromSeq dominates
//   - empty stream / replay disabled: tail only (DeliverNew)
//   - replay >= total: stream the whole thing (DeliverAll)
//   - replay < total: window slice (DeliverByStartSequence at LastSeq-replay+1)
func TestPickDeliverPolicy(t *testing.T) {
	tests := []struct {
		name         string
		replay       int
		startFromSeq uint64
		lastSeq      uint64
		wantPolicy   jetstream.DeliverPolicy
		wantStart    uint64
	}{
		{"resume dominates everything", 100, 42, 1000, jetstream.DeliverByStartSequencePolicy, 42},
		{"resume at next message", 100, 1001, 1000, jetstream.DeliverByStartSequencePolicy, 1001},
		{"resume past end → stream reset, tail only", 0, 1500, 1000, jetstream.DeliverNewPolicy, 0},
		{"resume on empty (reset) stream → tail only", 100, 5, 0, jetstream.DeliverNewPolicy, 0},
		{"resume past end → replay window", 100, 900, 500, jetstream.DeliverByStartSequencePolicy, 401},
		{"empty stream → tail only", 100, 0, 0, jetstream.DeliverNewPolicy, 0},
		{"replay disabled → tail only", 0, 0, 500, jetstream.DeliverNewPolicy, 0},
		{"replay negative → tail only", -1, 0, 500, jetstream.DeliverNewPolicy, 0},
		{"replay >= total → all", 100, 0, 50, jetstream.DeliverAllPolicy, 0},
		{"replay == total → all", 100, 0, 100, jetstream.DeliverAllPolicy, 0},
		{"replay < total → windowed", 100, 0, 1000, jetstream.DeliverByStartSequencePolicy, 901},
		{"window includes seq 1", 100, 0, 101, jetstream.DeliverByStartSequencePolicy, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, start, err := pickDeliverPolicy(tc.replay, tc.startFromSeq, 1, tc.lastSeq, everyRecordMatches(tc.lastSeq))
			if err != nil {
				t.Fatal(err)
			}
			if policy != tc.wantPolicy {
				t.Errorf("policy = %v, want %v", policy, tc.wantPolicy)
			}
			if start != tc.wantStart {
				t.Errorf("optStart = %d, want %d", start, tc.wantStart)
			}
		})
	}
}

// everyRecordMatches is the pending function for a stream in which every
// sequence from 1 to lastSeq matches the subject.
func everyRecordMatches(lastSeq uint64) pendingFunc {
	return func(seq uint64) (uint64, error) {
		if seq > lastSeq {
			return 0, nil
		}
		return lastSeq - seq + 1, nil
	}
}

// TestReplayStart checks the replay boundary on random streams where some
// sequences match and others are gaps. A consumer starting at the boundary must
// receive exactly the newest n matches, as found by a full scan.
func TestReplayStart(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		firstSeq := 1 + uint64(rng.IntN(5))
		lastSeq := firstSeq + uint64(rng.IntN(40))
		var matches []uint64
		for seq := firstSeq; seq <= lastSeq; seq++ {
			if rng.IntN(3) == 0 {
				matches = append(matches, seq)
			}
		}
		pending := func(seq uint64) (uint64, error) {
			var c uint64
			for _, m := range matches {
				if m >= seq {
					c++
				}
			}
			return c, nil
		}
		n := 1 + uint64(rng.IntN(int(lastSeq)))

		start, ok, err := replayStart(n, firstSeq, lastSeq, pending)
		if err != nil {
			t.Fatal(err)
		}
		if wantOK := uint64(len(matches)) >= n; ok != wantOK {
			t.Fatalf("firstSeq=%d lastSeq=%d matches=%v n=%d: ok=%v, want %v", firstSeq, lastSeq, matches, n, ok, wantOK)
		}
		if !ok {
			continue
		}
		var got []uint64
		for _, m := range matches {
			if m >= start {
				got = append(got, m)
			}
		}
		if want := matches[len(matches)-int(n):]; !slices.Equal(got, want) {
			t.Fatalf("firstSeq=%d lastSeq=%d matches=%v n=%d: start=%d delivers %v, want %v", firstSeq, lastSeq, matches, n, start, got, want)
		}
	}
}

// Note: live publish/subscribe round-trips are not unit-tested here — they
// need a running NATS server with JetStream. live_test.go covers them when
// BASE_TEST_NATS_URL is set.

// ── Subscription cleanup ─────────────────────────────────────────────────────

type fakeDeleter struct {
	name   string
	ctxErr error
	hasDL  bool
	retErr error
	called int
}

func (f *fakeDeleter) DeleteConsumer(ctx context.Context, name string) error {
	f.called++
	f.name, f.ctxErr = name, ctx.Err()
	_, f.hasDL = ctx.Deadline()
	return f.retErr
}

// The subscription's context is normally cancelled by the time cleanup runs;
// the delete must still go out, under its own deadline.
func TestReleaseConsumer_DetachedFromCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &fakeDeleter{}
	releaseConsumer(ctx, d, "cons-1", nil)
	if d.called != 1 || d.name != "cons-1" {
		t.Fatalf("DeleteConsumer calls=%d name=%q", d.called, d.name)
	}
	if d.ctxErr != nil {
		t.Errorf("delete ran on a cancelled context: %v", d.ctxErr)
	}
	if !d.hasDL {
		t.Error("delete has no deadline")
	}
}

func TestReleaseConsumer_LogsFailureExceptNotFound(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	releaseConsumer(context.Background(), &fakeDeleter{retErr: jetstream.ErrConsumerNotFound}, "gone", log)
	if buf.Len() != 0 {
		t.Errorf("already-deleted consumer was logged: %q", buf.String())
	}
	releaseConsumer(context.Background(), &fakeDeleter{retErr: errors.New("boom")}, "c", log)
	if !strings.Contains(buf.String(), "cleanup failed") {
		t.Errorf("failure not logged: %q", buf.String())
	}
}
