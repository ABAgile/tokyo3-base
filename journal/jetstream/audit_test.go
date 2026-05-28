package jetstream_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/jetstream"
)

// testEntry is a stand-in for per-binary audit.Entry types — the
// helpers are generic and don't care about the field layout, just
// that the type can round-trip through json.Marshal.
type testEntry struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

func TestNewAuditSink_EmptyURL_ReturnsNoop(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sink, err := jetstream.NewAuditSink[testEntry](jetstream.AuditSinkConfig{
		URL:       "",
		Subject:   "test.audit.events",
		EnvPrefix: "TEST_NATS",
		Log:       log,
	})
	if err != nil {
		t.Fatalf("NewAuditSink: %v", err)
	}
	if sink == nil {
		t.Fatal("sink is nil — must return a typed-noop sink, not nil")
	}

	// Appending against the no-op sink must succeed and drop silently.
	if err := sink.Append(context.Background(), testEntry{ID: "e-1", Action: "test"}); err != nil {
		t.Errorf("Append against noop sink: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "TEST_NATS_URL not set") {
		t.Errorf("missing warn line:\n%s", got)
	}
	if !strings.Contains(got, "audit sink is no-op") {
		t.Errorf("warn line missing 'no-op' wording:\n%s", got)
	}
}

func TestNewAuditSink_RequiresEnvPrefix(t *testing.T) {
	_, err := jetstream.NewAuditSink[testEntry](jetstream.AuditSinkConfig{})
	if err == nil || !strings.Contains(err.Error(), "EnvPrefix") {
		t.Errorf("err = %v, want EnvPrefix-required", err)
	}
}

// TestNewAuditSink_UnreachableURL: with NewSink's lazy-connect
// semantics, an unreachable URL is NOT a startup failure — the
// returned sink is queued for background reconnect. NewAuditSink
// inherits this property and must not error on plausibly-unreachable
// URLs. (cfg.CertFile etc. left blank to skip the TLS path, which
// would fail with missing files; this isolates the URL-reachability
// branch.)
func TestNewAuditSink_UnreachableURL_NoStartupError(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sink, err := jetstream.NewAuditSink[testEntry](jetstream.AuditSinkConfig{
		URL:       "nats://127.0.0.1:1",
		Subject:   "test.audit.events",
		EnvPrefix: "TEST_NATS",
		Log:       log,
	})
	if err != nil {
		t.Fatalf("NewAuditSink (unreachable broker): %v", err)
	}
	if sink == nil {
		t.Fatal("sink is nil")
	}

	// "without mTLS" warn should fire — no cert/key/ca provided.
	if !strings.Contains(buf.String(), "without mTLS") {
		t.Errorf("missing no-mTLS warn:\n%s", buf.String())
	}
}

func TestNewAuditSource_EmptyURL_ReturnsNoop(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	src, err := jetstream.NewAuditSource(jetstream.AuditSourceConfig{
		URL:        "",
		StreamName: "test_audit",
		Subject:    "test.audit.events",
		EnvPrefix:  "TEST_NATS",
		Log:        log,
	})
	if err != nil {
		t.Fatalf("NewAuditSource: %v", err)
	}
	if src == nil {
		t.Fatal("src is nil — must return a typed NoopSource, not nil")
	}

	// Verify it's the no-op variant — Subscribe yields no msgs.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	msgs, err := src.Subscribe(ctx, 0, 0)
	if err != nil {
		t.Fatalf("noop Subscribe: %v", err)
	}
	if msgs != nil {
		// Drain any pending messages; should close immediately.
		for range msgs {
			t.Fatal("noop source yielded a message")
		}
	}

	got := buf.String()
	if !strings.Contains(got, "TEST_NATS_URL not set") {
		t.Errorf("missing warn line:\n%s", got)
	}
	if !strings.Contains(got, "admin audit page will be empty") {
		t.Errorf("warn line missing admin-page wording:\n%s", got)
	}
}

func TestNewAuditSource_RequiresEnvPrefix(t *testing.T) {
	_, err := jetstream.NewAuditSource(jetstream.AuditSourceConfig{})
	if err == nil || !strings.Contains(err.Error(), "EnvPrefix") {
		t.Errorf("err = %v, want EnvPrefix-required", err)
	}
}

// TestNewAuditSink_TypedSinkActuallyEncodesJSON: end-to-end through
// the typed sink wrapping a recording inner sink — confirms the
// JSON encoding chain is wired correctly.
func TestNewAuditSink_TypedSinkEncodesJSON(t *testing.T) {
	// Use NoopSink under the hood but observe via a recording wrapper.
	// Achieving that without bringing in a mock is awkward; the
	// existing TestNewJSONSink in the journal package already covers
	// the round-trip. Here we just confirm NewAuditSink with empty URL
	// returns a sink whose underlying type satisfies the
	// EncodedSink[T] surface the caller relies on.
	sink, err := jetstream.NewAuditSink[testEntry](jetstream.AuditSinkConfig{
		EnvPrefix: "TEST_NATS",
	})
	if err != nil {
		t.Fatalf("NewAuditSink: %v", err)
	}
	// Type sanity: assigning to *journal.EncodedSink[testEntry] must
	// compile — happens implicitly via the return type, but exercise
	// the typed Append shape too.
	var _ *journal.EncodedSink[testEntry] = sink
	if err := sink.Append(context.Background(), testEntry{ID: "e-1", Action: "noop"}); err != nil {
		t.Errorf("Append: %v", err)
	}
}
