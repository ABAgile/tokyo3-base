// Package journal provides the write face of an append-only, durable,
// ordered event journal — the right shape for audit trails, event-sourcing
// stores, financial ledgers, change-data-capture sinks, anything where
// "this event happened, never lose it" matters.
//
// A Sink is intentionally write-only. Reading the journal back (replay,
// query, projection) is a separate concern handled by the consumer side
// of whichever transport is in use; this package has no opinions about it.
//
// # Reliability contract
//
// Sink.Append publishes synchronously and returns the publish error to the
// caller. Implementations must not silently drop or swallow failures —
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
//   - journal/jetstream — NATS JetStream sync publish (recommended default)
//
// Future candidates: kafka, kinesis, file (single-server fallback), syslog.
package journal

import "context"

// Sink is the write face of an append-only journal. Append publishes
// payload synchronously and returns the publish error; Close releases the
// underlying transport.
type Sink interface {
	Append(ctx context.Context, payload []byte) error
	Close() error
}

// Noop discards every payload. Use in tests and in dev environments where
// no journal backend is configured. Append always returns nil — by design;
// callers that depend on real fail-closed semantics in production should
// not be wired to a Noop in production.
type Noop struct{}

func (Noop) Append(context.Context, []byte) error { return nil }
func (Noop) Close() error                         { return nil }
