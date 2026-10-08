package journal

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// DefaultTrackerSize is the ring cap when [TrackerConfig.Max] is unset. Old
// entries fall out as newer ones arrive — a Tracker surfaces recent activity,
// not full history.
const DefaultTrackerSize = 500

// Tracker maintains a bounded, newest-first in-memory ring of the most recent
// decoded events from a [Source], kept current by a background [Tracker.Run]
// loop. It is the materialized view behind a server-rendered "recent events"
// page — the SSR counterpart to journal/sse, which streams to a browser
// instead. [Tracker.Snapshot] reads are safe to call concurrently while Run is
// active.
type Tracker[T any] struct {
	src    Source
	decode func(Msg) (T, bool)
	less   func(a, b T) bool
	max    int
	label  string
	log    *slog.Logger
	retry  time.Duration

	mu   sync.RWMutex
	ring []T // newest first
}

// TrackerConfig wires a [Tracker].
type TrackerConfig[T any] struct {
	// Source is the journal source to subscribe to. Required.
	Source Source

	// Decode turns a raw Msg into a T. Return ok=false to skip the record —
	// both a decode failure and a filtered-out record (e.g. the wrong action)
	// use this path, so the caller owns any per-skip logging. Required.
	Decode func(Msg) (T, bool)

	// Less, when non-nil, keeps the ring ordered newest-first: Less(a, b)
	// reports whether a is newer than b. The ring is re-sorted on each ingest
	// (cheap at ring sizes). nil ⇒ arrival order — each new record is
	// prepended, which suits a stream whose publish order already matches
	// recency.
	Less func(a, b T) bool

	// Max caps the ring. 0 ⇒ [DefaultTrackerSize].
	Max int

	// Label is an optional identifier for the "subscribed" log line.
	Label string

	// Log is the structured logger. nil ⇒ slog.Default.
	Log *slog.Logger

	// ResubscribeWait, when > 0, makes [Tracker.Run] survive a source that
	// drops: if the source channel closes (or Subscribe fails) while ctx is
	// live, Run waits this long and subscribes again, resuming after the last
	// sequence it ingested so nothing is duplicated or skipped. 0 keeps the
	// legacy behaviour — a closed channel ends Run with a nil error — which
	// leaves the ring silently stale if the source died unexpectedly.
	ResubscribeWait time.Duration
}

// NewTracker validates cfg and returns a Tracker. Source and Decode are the
// hard requirements.
func NewTracker[T any](cfg TrackerConfig[T]) (*Tracker[T], error) {
	if cfg.Source == nil {
		return nil, errors.New("journal: tracker source is required")
	}
	if cfg.Decode == nil {
		return nil, errors.New("journal: tracker decode is required")
	}
	if cfg.Max <= 0 {
		cfg.Max = DefaultTrackerSize
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Tracker[T]{
		src:    cfg.Source,
		decode: cfg.Decode,
		less:   cfg.Less,
		max:    cfg.Max,
		label:  cfg.Label,
		log:    cfg.Log,
		retry:  cfg.ResubscribeWait,
	}, nil
}

// Run subscribes to the source — replaying the last Max records, then tailing
// — and ingests until ctx is cancelled or the source channel closes. Returns
// ctx.Err() on cancel and nil on a clean channel close. With
// [TrackerConfig.ResubscribeWait] set, a dropped source is resubscribed (from
// the last ingested sequence) instead of ending Run. Own the goroutine via
// [guard.Go] or a run.Group component.
func (t *Tracker[T]) Run(ctx context.Context) error {
	var lastSeq uint64
	for {
		replay, from := t.max, uint64(0)
		if lastSeq > 0 {
			replay, from = 0, lastSeq+1 // resume: don't replay what the ring already holds
		}
		ch, err := t.src.Subscribe(ctx, replay, from)
		if err == nil {
			t.log.Info("journal tracker subscribed", "label", t.label, "replay", replay, "from_seq", from)
			if err = t.ingest(ctx, ch, &lastSeq); err == nil && t.retry <= 0 {
				return nil
			}
			if err != nil {
				return err
			}
			t.log.Warn("journal tracker source closed; resubscribing", "label", t.label, "wait", t.retry)
		} else {
			if t.retry <= 0 || ctx.Err() != nil {
				return err
			}
			t.log.Warn("journal tracker subscribe failed; retrying", "label", t.label, "wait", t.retry, "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(t.retry):
		}
	}
}

// ingest drains ch into the ring, recording the newest sequence seen. It
// returns ctx.Err() on cancel and nil when the channel closes.
func (t *Tracker[T]) ingest(ctx context.Context, ch <-chan Msg, lastSeq *uint64) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				return nil
			}
			if msg.Seq > *lastSeq {
				*lastSeq = msg.Seq
			}
			if v, keep := t.decode(msg); keep {
				t.insert(v)
			}
		}
	}
}

// Snapshot returns a newest-first copy of the ring. Safe to call from request
// handlers while [Tracker.Run] is active.
func (t *Tracker[T]) Snapshot() []T {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]T, len(t.ring))
	copy(out, t.ring)
	return out
}

func (t *Tracker[T]) insert(v T) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.less != nil {
		t.ring = append(t.ring, v)
		sort.SliceStable(t.ring, func(i, j int) bool { return t.less(t.ring[i], t.ring[j]) })
	} else {
		// Prepend: the just-arrived record is newest.
		t.ring = append([]T{v}, t.ring...)
	}
	if len(t.ring) > t.max {
		t.ring = t.ring[:t.max]
	}
}
