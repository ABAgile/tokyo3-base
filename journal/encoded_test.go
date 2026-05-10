package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// captureSink stores every Append payload for inspection.
type captureSink struct{ payloads [][]byte }

func (s *captureSink) Append(_ context.Context, payload []byte) error {
	s.payloads = append(s.payloads, append([]byte(nil), payload...))
	return nil
}
func (s *captureSink) Close() error { return nil }

// errSink fails every Append. Lets us prove the inner Sink's error
// propagates through EncodedSink.
type errSink struct{}

func (errSink) Append(context.Context, []byte) error { return errors.New("inner publish failed") }
func (errSink) Close() error                         { return nil }

type sample struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// TestJSONSink_RoundTrip: encoded payload is the JSON of the input value.
func TestJSONSink_RoundTrip(t *testing.T) {
	cap := &captureSink{}
	s := NewJSONSink[sample](cap)

	in := sample{ID: "e-1", Name: "alice"}
	if err := s.Append(context.Background(), in); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if len(cap.payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(cap.payloads))
	}
	var out sample
	if err := json.Unmarshal(cap.payloads[0], &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", out, in)
	}
}

// TestEncodedSink_CustomEncoder: callers can pick any wire format.
func TestEncodedSink_CustomEncoder(t *testing.T) {
	cap := &captureSink{}
	// Toy "encoder": just dump T.Name as raw bytes.
	encode := func(v sample) ([]byte, error) { return []byte(v.Name), nil }
	s := NewEncodedSink(Sink(cap), encode)

	if err := s.Append(context.Background(), sample{Name: "bob"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if string(cap.payloads[0]) != "bob" {
		t.Errorf("got %q, want %q", cap.payloads[0], "bob")
	}
}

// TestEncodedSink_EncodeError: encode failures surface as Append errors,
// without reaching the inner Sink.
func TestEncodedSink_EncodeError(t *testing.T) {
	cap := &captureSink{}
	encode := func(_ sample) ([]byte, error) { return nil, errors.New("encode failed") }
	s := NewEncodedSink(Sink(cap), encode)

	err := s.Append(context.Background(), sample{})
	if err == nil {
		t.Fatal("expected encode error, got nil")
	}
	if !strings.Contains(err.Error(), "encode") {
		t.Errorf("expected error to mention 'encode', got %q", err)
	}
	if len(cap.payloads) != 0 {
		t.Errorf("inner Sink should not be called on encode failure; got %d payloads", len(cap.payloads))
	}
}

// TestEncodedSink_InnerError: inner.Append failures surface verbatim.
func TestEncodedSink_InnerError(t *testing.T) {
	s := NewJSONSink[sample](errSink{})
	if err := s.Append(context.Background(), sample{}); err == nil {
		t.Error("expected inner error, got nil")
	}
}

// TestEncodedSink_Close: Close is forwarded to the inner Sink.
func TestEncodedSink_Close(t *testing.T) {
	s := NewJSONSink[sample](NoopSink{})
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// staticSource yields the configured msgs in order then closes the channel
// (no live tail). Mirrors captureSink on the read side.
type staticSource struct {
	msgs []Msg
	// recorded args for assertions
	gotReplay   int
	gotStartSeq uint64
	closeCalled bool
}

func (s *staticSource) Subscribe(ctx context.Context, replay int, startFromSeq uint64) (<-chan Msg, error) {
	s.gotReplay = replay
	s.gotStartSeq = startFromSeq
	out := make(chan Msg)
	go func() {
		defer close(out)
		for _, m := range s.msgs {
			select {
			case <-ctx.Done():
				return
			case out <- m:
			}
		}
	}()
	return out, nil
}
func (s *staticSource) Close() error { s.closeCalled = true; return nil }

// errSource fails every Subscribe. Lets us prove the inner Source's error
// propagates through EncodedSource — symmetric to errSink above.
type errSource struct{}

func (errSource) Subscribe(context.Context, int, uint64) (<-chan Msg, error) {
	return nil, errors.New("inner subscribe failed")
}
func (errSource) Close() error { return nil }

// TestJSONSource_RoundTrip: inner Msg.Data containing JSON of T comes back
// as Event[T] with Seq, Time, and decoded Value preserved. Symmetric to
// TestJSONSink_RoundTrip.
func TestJSONSource_RoundTrip(t *testing.T) {
	in := sample{ID: "e-1", Name: "alice"}
	payload, _ := json.Marshal(in)
	when := time.Unix(1700000000, 0).UTC()

	src := &staticSource{msgs: []Msg{{Seq: 7, Time: when, Data: payload}}}
	s := NewJSONSource[sample](src)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	events, err := s.Subscribe(ctx, 100, 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	got, ok := <-events
	if !ok {
		t.Fatal("channel closed before delivering event")
	}
	if got.Seq != 7 {
		t.Errorf("Seq = %d, want 7", got.Seq)
	}
	if !got.Time.Equal(when) {
		t.Errorf("Time = %s, want %s", got.Time, when)
	}
	if got.Value != in {
		t.Errorf("Value = %+v, want %+v", got.Value, in)
	}

	// Subscribe args are forwarded verbatim to the inner Source.
	if src.gotReplay != 100 || src.gotStartSeq != 0 {
		t.Errorf("inner got replay=%d startSeq=%d, want 100, 0", src.gotReplay, src.gotStartSeq)
	}
}

// TestEncodedSource_CustomDecoder: callers can pick any wire format.
// Mirror of TestEncodedSink_CustomEncoder.
func TestEncodedSource_CustomDecoder(t *testing.T) {
	src := &staticSource{msgs: []Msg{{Seq: 1, Data: []byte("bob")}}}
	// Toy "decoder": treat the raw bytes as the Name field.
	decode := func(b []byte) (sample, error) { return sample{Name: string(b)}, nil }
	s := NewEncodedSource(Source(src), decode)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	events, err := s.Subscribe(ctx, 0, 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	e := <-events
	if e.Value.Name != "bob" {
		t.Errorf("got %+v, want Name=bob", e.Value)
	}
}

// TestEncodedSource_DecodeError: decode failures are silently dropped per
// the contract — a malformed record means "this consumer can't read it",
// not "abort the stream". Other records in the same subscription still
// flow through. Symmetric to (but inverted from) TestEncodedSink_EncodeError.
func TestEncodedSource_DecodeError(t *testing.T) {
	good, _ := json.Marshal(sample{Name: "alice"})
	src := &staticSource{msgs: []Msg{
		{Seq: 1, Data: []byte("not json")}, // dropped
		{Seq: 2, Data: good},               // forwarded
	}}
	s := NewJSONSource[sample](src)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	events, err := s.Subscribe(ctx, 0, 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	var got []Event[sample]
	for e := range events {
		got = append(got, e)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1 (the malformed one should be dropped)", len(got))
	}
	if got[0].Seq != 2 || got[0].Value.Name != "alice" {
		t.Errorf("got %+v, want Seq=2 Name=alice", got[0])
	}
}

// TestEncodedSource_InnerError: inner.Subscribe failures surface verbatim.
// Symmetric to TestEncodedSink_InnerError.
func TestEncodedSource_InnerError(t *testing.T) {
	s := NewJSONSource[sample](errSource{})
	if _, err := s.Subscribe(t.Context(), 100, 0); err == nil {
		t.Error("expected inner error, got nil")
	}
}

// TestEncodedSource_Close: Close is forwarded to the inner Source.
func TestEncodedSource_Close(t *testing.T) {
	src := &staticSource{}
	s := NewJSONSource[sample](src)
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if !src.closeCalled {
		t.Error("Close was not forwarded to inner Source")
	}
}

// TestEncodedSource_CtxCancelStopsDecoder: cancelling ctx mid-stream stops
// the decoder goroutine cleanly, even with messages still buffered upstream.
// The output channel must close shortly after; otherwise the decoder is
// leaking a goroutine.
func TestEncodedSource_CtxCancelStopsDecoder(t *testing.T) {
	good, _ := json.Marshal(sample{Name: "x"})
	// Many messages so the decoder is mid-stream when we cancel.
	msgs := make([]Msg, 100)
	for i := range msgs {
		msgs[i] = Msg{Seq: uint64(i + 1), Data: good}
	}
	src := &staticSource{msgs: msgs}
	s := NewJSONSource[sample](src)

	ctx, cancel := context.WithCancel(context.Background())
	events, err := s.Subscribe(ctx, 100, 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Read one to ensure the pipeline is live, then cancel and drain.
	if _, ok := <-events; !ok {
		t.Fatal("channel closed before any message")
	}
	cancel()
	deadline := time.After(time.Second)
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return // expected: channel closed
			}
		case <-deadline:
			t.Fatal("output channel did not close within 1s of ctx cancel")
		}
	}
}
