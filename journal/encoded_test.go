package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
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
	s := NewJSONSink[sample](Noop{})
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
