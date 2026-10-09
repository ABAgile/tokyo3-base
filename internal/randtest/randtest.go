// Package randtest makes crypto/rand fail on demand, so tests can reach the
// error paths of code that draws randomness.
//
// It swaps the process-wide crypto/rand.Reader for the duration of one call.
// Use it only from tests that do not run in parallel, and keep the function
// under test as the only work inside the swap: any other goroutine that draws
// randomness in that window will see the failure too.
//
// Do not call crypto/rand.Read inside the swap. Since Go 1.24 it does not
// return read errors; it crashes the process instead.
package randtest

import (
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"testing"
)

// ErrEntropy is the error the failing reader returns once its budget of
// successful reads is spent.
var ErrEntropy = errors.New("randtest: entropy unavailable")

type countReader struct {
	mu   sync.Mutex
	left int // reads that still succeed
	real io.Reader
}

func (r *countReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.left <= 0 {
		return 0, ErrEntropy
	}
	r.left--
	return r.real.Read(p)
}

// FailAfter runs fn with crypto/rand.Reader replaced by a reader that serves
// the next n reads from the real source and then fails with [ErrEntropy]. The
// original reader is restored before FailAfter returns, even if fn panics.
func FailAfter(t testing.TB, n int, fn func()) {
	t.Helper()
	prev := rand.Reader
	rand.Reader = &countReader{left: n, real: prev}
	defer func() { rand.Reader = prev }()
	fn()
}

type sizeReader struct {
	mu   sync.Mutex
	size int
	done bool // the read of size bytes has been served
	real io.Reader
}

func (r *sizeReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return 0, ErrEntropy
	}
	if len(p) == r.size {
		r.done = true
	}
	return r.real.Read(p)
}

// FailAfterSize runs fn with crypto/rand.Reader replaced by a reader that serves
// reads normally until it has served one read of exactly size bytes, and then
// fails every later read with [ErrEntropy]. Use it when a draw of a known size
// is followed by a draw that must fail. The original reader is restored before
// FailAfterSize returns, even if fn panics.
func FailAfterSize(t testing.TB, size int, fn func()) {
	t.Helper()
	prev := rand.Reader
	rand.Reader = &sizeReader{size: size, real: prev}
	defer func() { rand.Reader = prev }()
	fn()
}
