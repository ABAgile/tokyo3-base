package journal_test

import (
	"context"
	"encoding/json"
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
