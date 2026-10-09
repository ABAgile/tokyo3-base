package reloader

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// stamp is the mtime of each file behind a fileValue, in file order.
type stamp []time.Time

// equal reports whether s and o hold the same mtimes. Staleness is "mtime
// differs" rather than "mtime advanced": a replacement that carries an older or
// preserved mtime (cp -p, a restored backup) must still be picked up, as must a
// rotation that only touched one of the files.
func (s stamp) equal(o stamp) bool {
	if len(s) != len(o) {
		return false
	}
	for i := range s {
		if !s[i].Equal(o[i]) {
			return false
		}
	}
	return true
}

// fileValue is the hot-reload state machine behind [CertLoader] and [CALoader].
// It holds the last good value of one TLS input, read from one or more files,
// and re-reads the files when their mtimes change. A failed re-read keeps the
// last good value, so a rotation caught mid-write does not interrupt in-flight
// handshakes.
type fileValue[T any] struct {
	files []string
	// read loads and parses the files. raw is the source PEM, if the value has
	// one, and is handed to swapped.
	read func() (val T, raw []byte, err error)
	// swapped, when non-nil, is called after each successful load with the new
	// value, the raw PEM from read, and the first file's mtime (zero when stat
	// failed). It runs outside the lock.
	swapped func(val T, raw []byte, mtime time.Time)
	// failed, when non-nil, is called when a non-forced reload fails and the
	// last good value is kept. It runs outside the lock.
	failed func(err error)
	// maxStale, when non-nil, bounds how long the last good value is kept after
	// reloads start failing; zero or nil keeps it indefinitely.
	maxStale func() time.Duration

	mu     sync.RWMutex
	val    T
	loaded bool
	// loadedAt and failedAt are the file mtimes at the last successful load and
	// at the last failed load that kept a value. A failure whose files could not
	// be stat'ed records neither.
	loadedAt, failedAt stamp
	// statFailed records that the files could not be stat'ed while a value was
	// kept, so that state is reported once rather than on every call.
	statFailed bool
	// failSince is when the current run of failed reloads began; zero when the
	// last attempt succeeded. failErr is that run's most recent failure.
	failSince time.Time
	failErr   error
}

// get returns the current value, re-reading the files first when their mtimes
// have changed. forced skips the mtime gate. A failed re-read keeps the last good
// value. A non-forced call reports the failure through failed and returns the
// kept value; a forced call returns the failure along with the kept value.
func (f *fileValue[T]) get(forced bool) (T, error) {
	s, ok := f.stat()

	f.mu.RLock()
	if !forced && f.settledLocked(s, ok) {
		val, err := f.keptLocked(time.Now())
		f.mu.RUnlock()
		return val, err
	}
	f.mu.RUnlock()

	f.mu.Lock()
	// Double-check under the write lock: another caller may have reloaded.
	if !forced && f.settledLocked(s, ok) {
		val, err := f.keptLocked(time.Now())
		f.mu.Unlock()
		return val, err
	}

	val, raw, err := f.read()
	if err != nil {
		// Keep the last good value across a failed reload, for at most maxStale
		// once the failures began.
		if !f.loaded {
			f.mu.Unlock()
			var zero T
			return zero, err
		}
		if ok {
			f.failedAt = s
		}
		f.statFailed = !ok
		if f.failSince.IsZero() {
			f.failSince = time.Now()
		}
		f.failErr = err
		kept, keptErr := f.keptLocked(time.Now())
		f.mu.Unlock()
		if forced {
			return kept, err
		}
		if f.failed != nil {
			f.failed(err)
		}
		return kept, keptErr
	}
	f.val, f.loaded = val, true
	f.failSince, f.failErr, f.statFailed = time.Time{}, nil, false
	if ok {
		f.loadedAt = s
	}
	f.mu.Unlock()
	if f.swapped != nil {
		var mtime time.Time
		if ok {
			mtime = s[0]
		}
		f.swapped(val, raw, mtime)
	}
	return val, nil
}

// stat returns the mtime of each backing file, or false when any file cannot be
// stat'ed.
func (f *fileValue[T]) stat() (stamp, bool) {
	s := make(stamp, len(f.files))
	for i, path := range f.files {
		fi, err := os.Stat(path)
		if err != nil {
			return nil, false
		}
		s[i] = fi.ModTime()
	}
	return s, true
}

// settledLocked reports whether the files are unchanged since the last load
// attempt (successful, or failed with a value kept). A stat failure with a value
// kept is settled once it has been reported. Caller holds f.mu.
func (f *fileValue[T]) settledLocked(s stamp, ok bool) bool {
	if !f.loaded {
		return false
	}
	if !ok {
		return f.statFailed
	}
	return s.equal(f.loadedAt) || s.equal(f.failedAt)
}

// keptLocked returns the kept value, or the failure once failures have lasted
// longer than maxStale. Caller holds f.mu.
func (f *fileValue[T]) keptLocked(now time.Time) (T, error) {
	if f.maxStale != nil {
		if limit := f.maxStale(); limit > 0 && !f.failSince.IsZero() && now.Sub(f.failSince) > limit {
			var zero T
			return zero, fmt.Errorf("last good value kept past MaxStale %s: %w", limit, f.failErr)
		}
	}
	return f.val, nil
}
