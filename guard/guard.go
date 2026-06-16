// Package guard holds defensive helpers for the work a program does outside
// the request path: supervised goroutines and best-effort cleanup.
//
// A single unrecovered panic in any goroutine crashes the whole process, and
// net/http's per-request recovery only covers request handlers — not the
// background goroutines a program runs (reapers, sync loops, trackers). Go and
// Tick wrap that work in panic recovery and a structured error log so one bad
// code path logs instead of bringing the process down. Close is the cleanup
// companion: a best-effort Close of a value that may or may not be closeable.
package guard

import (
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
)

// Guarded wraps fn in panic recovery and returns the wrapped func WITHOUT
// launching it: a panic is recovered and logged with a stack trace under name,
// and the wrapped func returns instead of taking the whole process down. Use it
// to give recovered work to a launcher that owns the goroutine — most notably
// [sync.WaitGroup.Go] (so a recovered goroutine can also be joined at shutdown)
// or golang.org/x/sync/errgroup. When you just need fire-and-forget, use [Go].
func Guarded(log *slog.Logger, name string, fn func()) func() {
	return func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("goroutine panic recovered",
					"goroutine", name,
					"panic", fmt.Sprintf("%v", r),
					"stack", string(debug.Stack()))
			}
		}()
		fn()
	}
}

// Go runs fn in a new goroutine wrapped in panic recovery: a panic is
// recovered and logged with a stack trace under name, and the goroutine
// returns instead of taking the whole process down. Use it for every
// long-lived background goroutine (reapers, sync loops, trackers) that does
// NOT need to be joined at shutdown; when you need a join, hand
// [Guarded](log, name, fn) to a WaitGroup/errgroup instead.
//
// Pair it with Tick: Go is the outer backstop for the goroutine, Tick keeps a
// ticker firing when one iteration panics.
func Go(log *slog.Logger, name string, fn func()) {
	go Guarded(log, name, fn)()
}

// Tick runs one iteration of a reaper/sync loop wrapped in panic recovery, so
// the surrounding ticker keeps firing after a bad tick. Call it synchronously
// inside the loop body — the caller owns the goroutine (recovering at the
// goroutine level would kill the loop; recovering per-tick keeps it alive).
// Pair it with Go for the outer backstop.
func Tick(log *slog.Logger, name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("tick panic recovered — loop continues",
				"loop", name,
				"panic", fmt.Sprintf("%v", r),
				"stack", string(debug.Stack()))
		}
	}()
	fn()
}

// Close calls Close on v when v implements [io.Closer], silently dropping any
// error. Use it to release a value behind a polymorphic interface that may or
// may not be closeable — e.g. an audit sink that's a real JetStream client
// (with Close) or a no-op (without). Typically deferred.
func Close(v any) {
	if c, ok := v.(io.Closer); ok {
		_ = c.Close()
	}
}
