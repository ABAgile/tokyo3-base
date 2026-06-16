package guard

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// capture is a minimal slog.Handler that records emitted records and signals
// done on each Handle — lets a test synchronize on "the recover logged"
// without sleeping.
type capture struct {
	mu      sync.Mutex
	records []slog.Record
	done    chan struct{}
}

func newCapture() *capture { return &capture{done: make(chan struct{}, 4)} }

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	c.records = append(c.records, r)
	c.mu.Unlock()
	select {
	case c.done <- struct{}{}:
	default:
	}
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

func (c *capture) last(t *testing.T) slog.Record {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.records) == 0 {
		t.Fatal("no records captured")
	}
	return c.records[len(c.records)-1]
}

func attr(r slog.Record, key string) (slog.Value, bool) {
	var v slog.Value
	var ok bool
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			v, ok = a.Value, true
			return false
		}
		return true
	})
	return v, ok
}

func TestGo_RecoversPanicAndLogs(t *testing.T) {
	c := newCapture()
	Go(slog.New(c), "worker", func() { panic("boom") })

	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		t.Fatal("panic was not recovered + logged within 2s")
	}

	r := c.last(t)
	if r.Level != slog.LevelError {
		t.Errorf("level = %v, want ERROR", r.Level)
	}
	if r.Message != "goroutine panic recovered" {
		t.Errorf("message = %q", r.Message)
	}
	if v, ok := attr(r, "goroutine"); !ok || v.String() != "worker" {
		t.Errorf("goroutine attr = %v (ok=%v), want worker", v, ok)
	}
	if v, ok := attr(r, "stack"); !ok || v.String() == "" {
		t.Error("expected a non-empty stack attr")
	}
}

func TestGo_NoPanic_RunsFnNoLog(t *testing.T) {
	c := newCapture()
	ran := make(chan struct{})
	Go(slog.New(c), "worker", func() { close(ran) })

	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("fn did not run")
	}
	// Give any (erroneous) error log a beat to land, then assert silence.
	select {
	case <-c.done:
		t.Fatal("unexpected log on the no-panic path")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestGuarded_RecoversPanicAndLogs(t *testing.T) {
	c := newCapture()
	// Guarded returns a func; the caller owns the goroutine. Run it inline so a
	// missing recover would crash the test process.
	Guarded(slog.New(c), "worker", func() { panic("boom") })()

	r := c.last(t)
	if r.Level != slog.LevelError {
		t.Errorf("level = %v, want ERROR", r.Level)
	}
	if r.Message != "goroutine panic recovered" {
		t.Errorf("message = %q", r.Message)
	}
	if v, ok := attr(r, "goroutine"); !ok || v.String() != "worker" {
		t.Errorf("goroutine attr = %v (ok=%v), want worker", v, ok)
	}
}

func TestGuarded_JoinsViaWaitGroup(t *testing.T) {
	c := newCapture()
	// The whole point of Guarded: compose recovery with a join. A panicking
	// worker must still let wg.Wait() return (defer Done runs during unwind).
	var wg sync.WaitGroup
	wg.Go(Guarded(slog.New(c), "worker", func() { panic("boom") }))

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait did not return after a recovered panic")
	}
}

func TestTick_RecoversAndReturns(t *testing.T) {
	c := newCapture()
	// Must return rather than crash the test process.
	Tick(slog.New(c), "reaper", func() { panic("bad tick") })

	r := c.last(t)
	if r.Message != "tick panic recovered — loop continues" {
		t.Errorf("message = %q", r.Message)
	}
	if v, ok := attr(r, "loop"); !ok || v.String() != "reaper" {
		t.Errorf("loop attr = %v (ok=%v), want reaper", v, ok)
	}
}

func TestTick_NoPanic_RunsFn(t *testing.T) {
	c := newCapture()
	ran := false
	Tick(slog.New(c), "reaper", func() { ran = true })
	if !ran {
		t.Fatal("fn did not run")
	}
	if len(c.records) != 0 {
		t.Errorf("unexpected logs on the no-panic path: %d", len(c.records))
	}
}

func TestClose_CallsCloseOnCloser(t *testing.T) {
	c := &recordingCloser{}
	Close(c)
	if !c.closed {
		t.Error("Close did not call Close on a Closer-implementing value")
	}
}

func TestClose_NoOpOnNonCloser(t *testing.T) {
	// Must not panic on values that don't implement io.Closer.
	Close("not a closer")
	Close(42)
	Close(struct{}{})
}

func TestClose_NilSafe(t *testing.T) {
	// Untyped nil must not panic.
	Close(nil)
}

type recordingCloser struct{ closed bool }

func (r *recordingCloser) Close() error {
	r.closed = true
	return nil
}
