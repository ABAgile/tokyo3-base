package jetstream

import (
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
		{"resume on empty stream", 100, 5, 0, jetstream.DeliverByStartSequencePolicy, 5},
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
			policy, start := pickDeliverPolicy(tc.replay, tc.startFromSeq, tc.lastSeq)
			if policy != tc.wantPolicy {
				t.Errorf("policy = %v, want %v", policy, tc.wantPolicy)
			}
			if start != tc.wantStart {
				t.Errorf("optStart = %d, want %d", start, tc.wantStart)
			}
		})
	}
}

// Note: live publish/subscribe round-trips are not unit-tested here — they
// require a running NATS server with JetStream enabled and a stream
// covering the test subject. Cover that in an integration test (build tag)
// or via the docker compose stack already used by the broader project.
