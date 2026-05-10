package journal

import (
	"context"
	"testing"
	"time"
)

// TestNoopSink satisfies the Sink interface and exercises both methods.
// The assertion is that they don't error — NoopSink is by definition the
// always-succeed implementation.
func TestNoopSink(t *testing.T) {
	var s Sink = NoopSink{}
	if err := s.Append(context.Background(), []byte("data")); err != nil {
		t.Errorf("NoopSink.Append: %v", err)
	}
	if err := s.Append(context.Background(), nil); err != nil {
		t.Errorf("NoopSink.Append(nil): %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("NoopSink.Close: %v", err)
	}
}

// TestNoopSource is the read-side mirror: NoopSource satisfies the Source
// interface, never delivers a message, and closes the returned channel
// promptly when the caller cancels.
func TestNoopSource(t *testing.T) {
	var s Source = NoopSource{}
	ctx, cancel := context.WithCancel(context.Background())

	ch, err := s.Subscribe(ctx, 100, 0)
	if err != nil {
		t.Fatalf("NoopSource.Subscribe: %v", err)
	}
	if ch == nil {
		t.Fatal("NoopSource.Subscribe returned a nil channel")
	}

	// Before cancel: nothing should be delivered. Read with a tight timeout
	// — receiving anything (or seeing the channel close) is a contract
	// violation, since NoopSource is meant to behave like an idle stream.
	select {
	case m, ok := <-ch:
		if ok {
			t.Errorf("got %+v, want no message before cancel", m)
		} else {
			t.Error("channel closed before ctx cancel")
		}
	case <-time.After(10 * time.Millisecond):
		// expected — nothing arrived
	}

	// After cancel: channel must close so consumers exit cleanly.
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("got a message after cancel; want closed channel")
		}
	case <-time.After(time.Second):
		t.Fatal("channel did not close within 1s of ctx cancel")
	}

	if err := s.Close(); err != nil {
		t.Errorf("NoopSource.Close: %v", err)
	}
}
