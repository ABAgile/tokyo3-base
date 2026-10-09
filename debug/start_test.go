package debug

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime/trace"
	"strings"
	"testing"
	"time"
)

// freeAddr returns a loopback address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// waitFor polls cond until it holds, failing after five seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestStartServesAndShutsDownOnCancel(t *testing.T) {
	addr := freeAddr(t)
	buf := &lockedBuffer{}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	Start(ctx, Config{Addr: addr, Log: slog.New(slog.NewTextHandler(buf, nil))})

	waitFor(t, "diagnostics server to answer", func() bool {
		resp, err := http.Get("http://" + addr + "/debug/pprof/")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	if out := buf.String(); !strings.Contains(out, "unauthenticated") || !strings.Contains(out, addr) {
		t.Errorf("startup warning should name the address and the lack of auth, got: %q", out)
	}

	cancel()
	waitFor(t, "listener to close after cancel", func() bool {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return true
		}
		conn.Close()
		return false
	})
}

// A nil Log must fall back to slog.Default, so the startup warning reaches
// whatever logger the process installed.
func TestStartUsesDefaultLoggerWhenNil(t *testing.T) {
	buf := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	Start(ctx, Config{Addr: freeAddr(t)})
	waitFor(t, "startup line on the default logger", func() bool {
		return strings.Contains(buf.String(), "diagnostics server listening")
	})
}

// A listen failure is logged rather than crashing the process.
func TestStartLogsListenFailure(t *testing.T) {
	buf := &lockedBuffer{}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	Start(ctx, Config{Addr: "127.0.0.1:not-a-port", Log: slog.New(slog.NewTextHandler(buf, nil))})
	waitFor(t, "listen failure to be logged", func() bool {
		return strings.Contains(buf.String(), "diagnostics server exited")
	})
}

func TestStartLogsRuntimeStatsOnInterval(t *testing.T) {
	buf := &lockedBuffer{}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	Start(ctx, Config{Addr: freeAddr(t), Log: slog.New(slog.NewTextHandler(buf, nil)), StatsEvery: 5 * time.Millisecond})
	waitFor(t, "a runtime stats line", func() bool {
		return strings.Contains(buf.String(), "runtime stats")
	})
}

// time.NewTicker panics on a non-positive duration, so zero and negative
// intervals must fall back to the default rather than reach the ticker. The
// ticker is created on the stats goroutine, so the test waits briefly for it
// to start before cancelling. A regression panics that goroutine and fails the
// whole test binary.
func TestStartDefaultsNonPositiveStatsInterval(t *testing.T) {
	for _, every := range []time.Duration{0, -time.Second} {
		ctx, cancel := context.WithCancel(t.Context())
		Start(ctx, Config{Addr: "127.0.0.1:not-a-port", Log: discardLogger(), StatsEvery: every})
		time.Sleep(100 * time.Millisecond)
		cancel()
	}
}

// The package doc promises that importing it registers nothing on
// http.DefaultServeMux, so profiling cannot attach to a binary by accident.
func TestNothingRegisteredOnDefaultServeMux(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	Start(ctx, Config{Addr: freeAddr(t), Log: discardLogger()})

	for _, path := range []string{"/debug/pprof/", "/debug/pprof/profile", "/debug/pprof/trace"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if _, pattern := http.DefaultServeMux.Handler(req); pattern != "" {
			t.Errorf("%s is registered on http.DefaultServeMux as %q", path, pattern)
		}
	}
}

// A diagnostics request still running when the shutdown timeout expires must not
// outlive the server. Its profile must stop, or the next one cannot start.
func TestStartStopsActiveTraceWhenShutdownTimesOut(t *testing.T) {
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	Start(ctx, Config{Addr: addr, Log: discardLogger()})
	waitFor(t, "diagnostics server to answer", func() bool {
		resp, err := http.Get("http://" + addr + "/debug/pprof/")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	go func() {
		resp, err := http.Get("http://" + addr + "/debug/pprof/trace?seconds=120")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	time.Sleep(200 * time.Millisecond) // let the trace start
	cancel()

	waitFor(t, "trace to stop after shutdown", func() bool {
		if err := trace.Start(io.Discard); err != nil {
			return false
		}
		trace.Stop()
		return true
	})
}
