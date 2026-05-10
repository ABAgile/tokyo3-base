package journal

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
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

// Event is the typed read counterpart to a Sink Append. Seq + Time come from
// the underlying transport (see Msg); Value is the decoded payload.
type Event[T any] struct {
	Seq   uint64
	Time  time.Time
	Value T
}

// EncodedSource wraps a Source with a typed Subscribe, decoding T from bytes
// via the configured decode function before forwarding to the caller.
// Symmetric to EncodedSink and intentionally narrow: the wire format is
// opaque to EncodedSource, just like EncodedSink. Use NewJSONSource for the
// common JSON case.
type EncodedSource[T any] struct {
	inner  Source
	decode func([]byte) (T, error)
}

// NewEncodedSource wraps inner with the given decode function. Subscribe
// delivers Event[T] values whose Value has been decoded from each Msg.Data.
func NewEncodedSource[T any](inner Source, decode func([]byte) (T, error)) *EncodedSource[T] {
	return &EncodedSource[T]{inner: inner, decode: decode}
}

// NewJSONSource is the JSON convenience: equivalent to NewEncodedSource with
// json.Unmarshal as the decoder.
func NewJSONSource[T any](inner Source) *EncodedSource[T] {
	return NewEncodedSource(inner, func(b []byte) (T, error) {
		var v T
		if err := json.Unmarshal(b, &v); err != nil {
			return v, err
		}
		return v, nil
	})
}

// Subscribe forwards to the inner Source and pipes through a decoder
// goroutine. Decode failures are dropped (with no surface to the caller —
// the wire format is the producer's contract; a decode failure means the
// stream contains a record this consumer can't read, and the recovery is
// to fix the producer or the type T, not to retry). Closes the returned
// channel when the inner channel closes.
func (s *EncodedSource[T]) Subscribe(ctx context.Context, replay int, startFromSeq uint64) (<-chan Event[T], error) {
	raw, err := s.inner.Subscribe(ctx, replay, startFromSeq)
	if err != nil {
		return nil, err
	}
	out := make(chan Event[T])
	go func() {
		defer close(out)
		for m := range raw {
			v, err := s.decode(m.Data)
			if err != nil {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case out <- Event[T]{Seq: m.Seq, Time: m.Time, Value: v}:
			}
		}
	}()
	return out, nil
}

// Close drains the inner Source.
func (s *EncodedSource[T]) Close() error {
	return s.inner.Close()
}
