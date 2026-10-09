package ratelimit

import (
	"log/slog"
	"strconv"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestNew_DefaultsBurstAndLogger(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 0})
	if l.burst != 1 {
		t.Errorf("burst = %d, want the minimum of 1 when unset", l.burst)
	}
	if l.log != slog.Default() {
		t.Error("nil Log did not fall back to slog.Default()")
	}
}

// Idle buckets must be evicted, or a stream of distinct sources grows the map
// without bound. Buckets used recently must survive the same sweep.
func TestSweep_EvictsIdleBucketsAndKeepsRecentOnes(t *testing.T) {
	l := New(Config{RPS: 10, Burst: 5, Log: discard()})
	t0 := time.Unix(0, 0)

	l.allow("idle", t0) // first sweep runs here and sets lastSweep
	l.allow("warm", t0.Add(10*time.Minute))
	l.allow("warm", t0.Add(25*time.Minute)) // refresh: existing key, no sweep
	// 31 minutes in: "idle" has been unused past idleTTL, "warm" has not.
	l.allow("new", t0.Add(31*time.Minute))

	if _, ok := l.buckets["idle"]; ok {
		t.Error("idle bucket survived a sweep past idleTTL")
	}
	for _, k := range []string{"warm", "new"} {
		if _, ok := l.buckets[k]; !ok {
			t.Errorf("bucket %q was evicted while still in use", k)
		}
	}
}

// Once the map is at its cap, overflow sources share one bucket, and throttle
// log lines for them are sampled the same way as for any other source. Otherwise
// a flood of distinct sources would produce a log line per rejected request.
func TestWarnDue_OverflowSourcesAreSampled(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 1, Log: discard()})
	now := time.Unix(0, 0)
	for i := range maxBuckets {
		l.buckets[strconv.Itoa(i)] = &bucket{lim: rate.NewLimiter(1, 1), seen: now}
	}
	l.allow("new-a", now) // creates the shared overflow bucket

	if due, _ := l.warnDue("new-b", now); !due {
		t.Fatal("first throttle line for an overflow source should be due")
	}
	if due, _ := l.warnDue("new-c", now.Add(time.Second)); due {
		t.Error("second overflow throttle line within warnInterval was not sampled")
	}
}

// A throttled key that has no bucket at all (e.g. one swept away between the
// decision and the log) has no sampling state, so its line is always due.
func TestWarnDue_UnknownKeyWithNoOverflowBucketAlwaysDue(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 1, Log: discard()})
	now := time.Unix(0, 0)
	for range 2 {
		due, suppressed := l.warnDue("never-seen", now)
		if !due || suppressed != 0 {
			t.Errorf("warnDue(unknown) = (%v, %d), want (true, 0)", due, suppressed)
		}
	}
}
