package jetstream

import "testing"

// TestNew_MissingURL covers the fast-fail config validation: empty URL
// must error before any network attempt.
func TestNew_MissingURL(t *testing.T) {
	if _, err := New(Config{Subject: "events"}); err == nil {
		t.Error("expected error for missing URL, got nil")
	}
}

// TestNew_MissingSubject covers the second config check: a URL without a
// subject must error before reaching nats.Connect.
func TestNew_MissingSubject(t *testing.T) {
	if _, err := New(Config{URL: "nats://localhost:4222"}); err == nil {
		t.Error("expected error for missing Subject, got nil")
	}
}

// Note: live publish round-trip is not unit-tested here — it requires a
// running NATS server with JetStream enabled and a stream covering the
// test subject. Cover that in an integration test (build tag) or via the
// docker compose stack already used by the broader project.
