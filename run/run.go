// Package run coordinates a daemon's long-lived components — the SSH server,
// HTTP listeners, tunnel dialers, pollers — under one shutdown discipline:
// run them concurrently, let the first to exit bring the rest down, and report
// the first real error. It replaces the per-daemon hand-rolled errCh + select
// + cancel scaffolding the binaries previously each carried.
package run

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Component is a long-lived unit of work bound to a context. It must return
// when its context is cancelled. A nil return means a clean, intentional exit.
type Component func(context.Context) error

// Group runs every component concurrently against a child of ctx. The first
// component to return — for ANY reason, error or nil — cancels that child,
// signalling the rest to wind down. Group then waits for all components to
// return and reports the first non-nil error that is not [context.Canceled]
// (the expected result of the group-initiated cancel).
//
// The cancellation is scoped to the group's own child context, so siblings the
// caller runs on the parent ctx (e.g. best-effort pollers via guard.Go) are
// NOT torn down by a component exit — they stop on the parent's own
// cancellation (a signal) or when the process exits. Pass each component a
// context-aware run loop; a component that ignores its context will stall
// Group's wait.
func Group(ctx context.Context, components ...Component) error {
	if len(components) == 0 {
		return nil
	}
	gctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, len(components))
	var wg sync.WaitGroup
	for _, c := range components {
		wg.Go(func() {
			err := c(gctx)
			cancel() // any exit brings the rest down
			errCh <- err
		})
	}
	wg.Wait()
	close(errCh)

	var first error
	for err := range errCh {
		if first == nil && err != nil && !errors.Is(err, context.Canceled) {
			first = err
		}
	}
	return first
}

// HTTPServer adapts an *http.Server into a [Component]: it serves until ctx is
// cancelled, then gracefully shuts down within shutdownTimeout. http.ErrServerClosed
// (the expected result of Shutdown) is folded to nil. Set useTLS for
// ListenAndServeTLS (the server's TLSConfig is the cert source, so the cert/key
// args are empty); otherwise plain ListenAndServe.
func HTTPServer(srv *http.Server, shutdownTimeout time.Duration, useTLS bool) Component {
	return func(ctx context.Context) error {
		serveErr := make(chan error, 1)
		go func() {
			if useTLS {
				serveErr <- srv.ListenAndServeTLS("", "")
			} else {
				serveErr <- srv.ListenAndServe()
			}
		}()
		select {
		case err := <-serveErr:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			return srv.Shutdown(shutdownCtx)
		}
	}
}
