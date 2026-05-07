package journal

import (
	"context"
	"encoding/json"
	"fmt"
)

// EncodedSink wraps a Sink with a typed Append, encoding T to bytes via
// the configured encode function before forwarding to the inner Sink.
//
// This is the right shape for any domain that has a typed event struct and
// a wire format — audit entries, event-sourcing events, CDC change records,
// ledger transactions. The wire format is opaque to EncodedSink: pass any
// `func(T) ([]byte, error)` (json.Marshal, proto.Marshal, custom binary,
// length-prefixed CSV …). Use NewJSONSink for the common JSON case.
type EncodedSink[T any] struct {
	inner  Sink
	encode func(T) ([]byte, error)
}

// NewEncodedSink wraps inner with the given encode function. Append serialises
// the value via encode and forwards the resulting bytes to inner.Append.
func NewEncodedSink[T any](inner Sink, encode func(T) ([]byte, error)) *EncodedSink[T] {
	return &EncodedSink[T]{inner: inner, encode: encode}
}

// NewJSONSink is the JSON convenience: equivalent to NewEncodedSink with
// json.Marshal as the encoder. Use when T is JSON-serialisable.
func NewJSONSink[T any](inner Sink) *EncodedSink[T] {
	return NewEncodedSink(inner, func(v T) ([]byte, error) { return json.Marshal(v) })
}

// Append encodes v and forwards the bytes to the inner Sink. Returns the
// encode error or the inner Sink's publish error — fail-closed semantics
// inherited from Sink.Append.
func (s *EncodedSink[T]) Append(ctx context.Context, v T) error {
	payload, err := s.encode(v)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	return s.inner.Append(ctx, payload)
}

// Close drains the inner Sink.
func (s *EncodedSink[T]) Close() error {
	return s.inner.Close()
}
