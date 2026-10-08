package journal_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"
)

// feedSource is a journal.Source that emits a fixed list of Msgs then closes
// the channel, so Tracker.Run drains every record and returns nil — making the
// tests deterministic with no polling.
type feedSource struct{ msgs []journal.Msg }

func (f *feedSource) Subscribe(_ context.Context, _ int, _ uint64) (<-chan journal.Msg, error) {
	ch := make(chan journal.Msg, len(f.msgs))
	for _, m := range f.msgs {
		ch <- m
	}
	close(ch)
	return ch, nil
}
func (f *feedSource) Close() error { return nil }

type event struct {
	Action string    `json:"action"`
	At     time.Time `json:"at"`
}

func jmsg(t *testing.T, seq uint64, action string, at time.Time) journal.Msg {
	t.Helper()
	b, err := json.Marshal(event{Action: action, At: at})
	if err != nil {
		t.Fatal(err)
	}
	return journal.Msg{Seq: seq, Data: b}
}

func decodeEvent(m journal.Msg) (event, bool) {
	var e event
	if err := json.Unmarshal(m.Data, &e); err != nil || e.Action == "" {
		return event{}, false
	}
	return e, true
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func runTracker[T any](t *testing.T, tr *journal.Tracker[T]) {
	t.Helper()
	if err := tr.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestTracker_SortNewestFirstByLess(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Emitted out of timestamp order; Less must reorder newest-first.
	src := &feedSource{msgs: []journal.Msg{
		jmsg(t, 1, "a", base.Add(1*time.Minute)),
		jmsg(t, 2, "b", base.Add(3*time.Minute)),
		jmsg(t, 3, "c", base.Add(2*time.Minute)),
	}}
	tr, err := journal.NewTracker(journal.TrackerConfig[event]{
		Source: src, Decode: decodeEvent, Log: discard(),
		Less: func(a, b event) bool { return a.At.After(b.At) },
	})
	if err != nil {
		t.Fatal(err)
	}
	runTracker(t, tr)

	got := tr.Snapshot()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].Action != "b" || got[1].Action != "c" || got[2].Action != "a" {
		t.Errorf("order = %v, want [b c a] (newest-first by At)", []string{got[0].Action, got[1].Action, got[2].Action})
	}
}

func TestTracker_ArrivalOrderWhenNoLess(t *testing.T) {
	src := &feedSource{msgs: []journal.Msg{
		jmsg(t, 1, "first", time.Time{}),
		jmsg(t, 2, "second", time.Time{}),
	}}
	tr, err := journal.NewTracker(journal.TrackerConfig[event]{
		Source: src, Decode: decodeEvent, Log: discard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	runTracker(t, tr)

	got := tr.Snapshot()
	if len(got) != 2 || got[0].Action != "second" || got[1].Action != "first" {
		t.Fatalf("arrival-order snapshot = %+v, want [second first]", got)
	}
}

func TestTracker_EvictsBeyondMax(t *testing.T) {
	var msgs []journal.Msg
	for i := 1; i <= 5; i++ {
		msgs = append(msgs, jmsg(t, uint64(i), string(rune('a'+i-1)), time.Time{}))
	}
	tr, err := journal.NewTracker(journal.TrackerConfig[event]{
		Source: &feedSource{msgs: msgs}, Decode: decodeEvent, Log: discard(), Max: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	runTracker(t, tr)

	got := tr.Snapshot()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (capped)", len(got))
	}
	// Newest three by arrival, newest-first: e, d, c.
	if got[0].Action != "e" || got[2].Action != "c" {
		t.Errorf("cap retained wrong window: %v", []string{got[0].Action, got[1].Action, got[2].Action})
	}
}

func TestTracker_DecodeSkip(t *testing.T) {
	src := &feedSource{msgs: []journal.Msg{
		{Seq: 1, Data: []byte("not json")}, // decode failure → skip
		jmsg(t, 2, "", time.Time{}),        // empty action → filtered
		jmsg(t, 3, "kept", time.Time{}),    // kept
	}}
	tr, err := journal.NewTracker(journal.TrackerConfig[event]{
		Source: src, Decode: decodeEvent, Log: discard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	runTracker(t, tr)

	got := tr.Snapshot()
	if len(got) != 1 || got[0].Action != "kept" {
		t.Fatalf("snapshot = %+v, want only [kept]", got)
	}
}

func TestNewTracker_Validation(t *testing.T) {
	if _, err := journal.NewTracker(journal.TrackerConfig[event]{Decode: decodeEvent}); err == nil {
		t.Error("want error when Source is nil")
	}
	if _, err := journal.NewTracker(journal.TrackerConfig[event]{Source: &feedSource{}}); err == nil {
		t.Error("want error when Decode is nil")
	}
}

// dropSource closes each subscription after its batch; it records the
// (replay, startFromSeq) of every Subscribe so resume behaviour is observable.
type dropSource struct {
	batches [][]journal.Msg
	calls   [][2]uint64
	done    chan struct{}
}

func (d *dropSource) Subscribe(ctx context.Context, replay int, from uint64) (<-chan journal.Msg, error) {
	d.calls = append(d.calls, [2]uint64{uint64(replay), from})
	i := len(d.calls) - 1
	if i >= len(d.batches) {
		close(d.done)
		ch := make(chan journal.Msg)
		go func() { <-ctx.Done(); close(ch) }()
		return ch, nil
	}
	ch := make(chan journal.Msg, len(d.batches[i]))
	for _, m := range d.batches[i] {
		ch <- m
	}
	close(ch)
	return ch, nil
}
func (d *dropSource) Close() error { return nil }

func TestTracker_ResubscribesFromLastSeq(t *testing.T) {
	now := time.Now()
	src := &dropSource{
		batches: [][]journal.Msg{
			{jmsg(t, 4, "a", now), jmsg(t, 5, "b", now)},
			{jmsg(t, 6, "c", now)},
		},
		done: make(chan struct{}),
	}
	tr, err := journal.NewTracker(journal.TrackerConfig[event]{
		Source: src, Decode: decodeEvent, Max: 10, Log: discard(), ResubscribeWait: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	select {
	case <-src.done:
	case <-time.After(5 * time.Second):
		t.Fatal("tracker never resubscribed a third time")
	}
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}

	want := [][2]uint64{{10, 0}, {10, 6}, {10, 7}}
	if len(src.calls) != len(want) {
		t.Fatalf("Subscribe calls = %v, want %v", src.calls, want)
	}
	for i := range want {
		if src.calls[i] != want[i] {
			t.Errorf("call %d = %v, want %v", i, src.calls[i], want[i])
		}
	}
	if got := tr.Snapshot(); len(got) != 3 {
		t.Errorf("ring has %d events, want 3 (no duplicates): %+v", len(got), got)
	}
}

// resetSource serves one batch per Subscribe call and records the resume
// points it was asked for, then ends the stream.
type resetSource struct {
	batches [][]journal.Msg
	froms   []uint64
	replays []int
}

func (s *resetSource) Subscribe(_ context.Context, replay int, from uint64) (<-chan journal.Msg, error) {
	s.froms = append(s.froms, from)
	s.replays = append(s.replays, replay)
	i := len(s.froms) - 1
	ch := make(chan journal.Msg, 8)
	if i < len(s.batches) {
		for _, m := range s.batches[i] {
			ch <- m
		}
	}
	close(ch)
	return ch, nil
}

// A recreated stream restarts at sequence 1; the resume point must follow it
// instead of staying pinned to the old high-water mark.
func TestTracker_ResumePointFollowsStreamReset(t *testing.T) {
	now := time.Now()
	src := &resetSource{batches: [][]journal.Msg{
		{jmsg(t, 100, "a", now), jmsg(t, 101, "b", now)},
		{jmsg(t, 1, "c", now)},
	}}
	tr, err := journal.NewTracker(journal.TrackerConfig[event]{
		Source: src, Decode: decodeEvent, Log: discard(), ResubscribeWait: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = tr.Run(ctx)
	if len(src.froms) < 3 || src.froms[1] != 102 || src.froms[2] != 2 {
		t.Fatalf("resume points = %v, want [0 102 2 ...]", src.froms)
	}
}

func (s *resetSource) Close() error { return nil }

// After a stream reset the ring must not keep the old stream's events, and the
// resubscribe must still offer the replay window for the new stream.
func TestTracker_StreamResetDropsStaleRingAndKeepsReplayWindow(t *testing.T) {
	now := time.Now()
	src := &resetSource{batches: [][]journal.Msg{
		{jmsg(t, 100, "old-a", now), jmsg(t, 101, "old-b", now)},
		{jmsg(t, 1, "new-a", now), jmsg(t, 2, "new-b", now)},
	}}
	tr, err := journal.NewTracker(journal.TrackerConfig[event]{
		Source: src, Decode: decodeEvent, Log: discard(), Max: 7, ResubscribeWait: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = tr.Run(ctx)

	got := tr.Snapshot()
	if len(got) != 2 || got[0].Action != "new-b" || got[1].Action != "new-a" {
		t.Fatalf("ring after reset = %+v, want only the new stream's [new-b new-a]", got)
	}
	if len(src.replays) < 2 || src.replays[1] != 7 {
		t.Fatalf("resume replay windows = %v, want the full Max (7) offered on resume", src.replays)
	}
}
