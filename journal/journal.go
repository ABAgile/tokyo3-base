// Package journal provides the read and write faces of an append-only,
// durable, ordered event journal — the right shape for audit trails,
// event-sourcing stores, financial ledgers, change-data-capture sinks,
// anything where "this event happened, never lose it" matters.
//
// Two interfaces, one journal:
//
//   - Sink   — write face. Append publishes one record synchronously.
//   - Source — read face. Subscribe yields historical + live records.
//
// They are independent: a producer needs only Sink, a viewer needs only
// Source, a consumer-projector pipeline can use Sink (republish) without
// Source. Implementations that supply both live in sub-packages so each
// transport's SDK weight is opt-in.
//
// # Reliability contract
//
// Sink.Append publishes synchronously and returns the publish error to
// the caller. Implementations must not silently drop or swallow failures —
// callers rely on Append's error to decide whether the originating
// operation may be considered complete. This is the fail-closed property
// that makes a journal usable as compliance evidence or as the source of
// truth for an event-sourced system.
//
// For lossy fire-and-forget application logs (observability), use a
// different primitive — base.AppLogger with WithAsyncNats covers that
// reliability tier. Mixing the two contracts under one interface erodes
// both.
//
// # Implementations
//
// The interface is byte-oriented; callers marshal their own payload format
// (JSON, protobuf, length-prefixed binary, …). Implementations live in
// sub-packages so each transport's SDK weight is opt-in:
//
//   - journal/jetstream — NATS JetStream sync publish + ephemeral consumer
//     read (recommended default).
//
// Future candidates: kafka, kinesis, file (single-server fallback), syslog.
package journal

import (
	"context"
	"time"
)

// ── Write face ────────────────────────────────────────────────────────────────

// Sink is the write face of an append-only journal. Append publishes
// payload synchronously and returns the publish error; Close releases the
// underlying transport.
type Sink interface {
	Append(ctx context.Context, payload []byte) error
	Close() error
}

// NoopSink discards every payload. Use in tests and in dev environments
// where no journal backend is configured. Append always returns nil — by
// design; callers that depend on real fail-closed semantics in production
// should not be wired to a NoopSink in production.
type NoopSink struct{}

func (NoopSink) Append(context.Context, []byte) error { return nil }
func (NoopSink) Close() error                         { return nil }

// ── Read face ─────────────────────────────────────────────────────────────────

// Msg is one record read back from a journal. Seq is a monotonic per-stream
// sequence number assigned by the underlying transport (JetStream stream
// sequence, Kafka offset, file line number — whatever the implementation
// chooses) so consumers can resume after disconnect by remembering the last
// Seq they saw. Time is the publish time stamped by the transport, not by
// the producer; producers that need their own timestamp should put it in
// Data. Data is the raw payload, byte-for-byte as the corresponding
// Sink.Append call delivered it.
type Msg struct {
	Seq  uint64
	Time time.Time
	Data []byte
}

// Source is the read counterpart to Sink. Subscribe yields a channel of
// Msgs in publish order, blending a backfill window of historical records
// with a live tail of new records, until the caller cancels ctx.
//
// Backfill semantics: if startFromSeq > 0 the implementation streams from
// that sequence onward (used to resume after a client disconnect via the
// SSE Last-Event-ID header, for example). Otherwise it streams the most
// recent `replay` records — clamped to whatever's available — followed by
// new records. replay <= 0 means "no backfill, tail only".
//
// Lifecycle: implementations clean up the underlying transport-level
// consumer when ctx is cancelled or the returned channel is no longer
// being read from. Close releases any process-wide resources (NATS
// connection, background goroutines) — call once, after all per-request
// Subscribe calls have ended.
type Source interface {
	Subscribe(ctx context.Context, replay int, startFromSeq uint64) (<-chan Msg, error)
	Close() error
}

// NoopSource yields no messages and never errors. The returned channel is
// closed when ctx is cancelled — useful as a stand-in for tests and dev
// environments where no journal backend is configured. Mirrors NoopSink
// on the write side.
type NoopSource struct{}

// Subscribe returns a channel that closes only when ctx is cancelled.
func (NoopSource) Subscribe(ctx context.Context, _ int, _ uint64) (<-chan Msg, error) {
	ch := make(chan Msg)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, nil
}

// Close is a no-op.
func (NoopSource) Close() error { return nil }
