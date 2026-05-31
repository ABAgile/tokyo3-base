// Package debug runs an opt-in diagnostics HTTP server exposing Go
// runtime profiles (goroutine, heap, threadcreate, CPU, trace, …) plus a
// periodic runtime-stats log line, for chasing leaks and stalls.
//
// Unlike net/http/pprof, this package registers nothing on
// http.DefaultServeMux: it builds the profile handlers directly from
// runtime/pprof + runtime/trace and serves them on its own mux, so
// importing it can never quietly attach profiling to a binary that
// happens to serve the default mux. The server only starts when
// Config.Addr is non-empty, so importing the package is otherwise inert.
package debug

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"strings"
	"time"
)

const defaultStatsInterval = 30 * time.Second

// Config configures the diagnostics server.
type Config struct {
	// Addr is the listen address for the diagnostics HTTP server, e.g.
	// "127.0.0.1:6060" or ":6060". Empty disables everything (no
	// listener, no stats loop) — wire it from a per-app env var so it
	// stays off by default in production.
	Addr string
	// Log receives the startup line and the periodic runtime stats.
	// Defaults to slog.Default() when nil.
	Log *slog.Logger
	// StatsEvery is the runtime-stats logging interval. Defaults to 30s.
	StatsEvery time.Duration
}

// Start launches the diagnostics server on cfg.Addr (when non-empty) and
// a goroutine that logs goroutine / OS-thread / heap counts every
// cfg.StatsEvery. Both stop when ctx is cancelled. It is a no-op when
// cfg.Addr is empty.
//
// WARNING: the endpoints are unauthenticated. Bind Addr to loopback or a
// private interface and never expose it publicly.
func Start(ctx context.Context, cfg Config) {
	if cfg.Addr == "" {
		return
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	every := cfg.StatsEvery
	if every <= 0 {
		every = defaultStatsInterval
	}

	srv := &http.Server{Addr: cfg.Addr, Handler: Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	go func() {
		log.Warn("diagnostics server listening — unauthenticated, do NOT expose publicly", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("diagnostics server exited", "err", err)
		}
	}()
	go logRuntimeStats(ctx, log, every)
}

// Handler returns the diagnostics mux (profiles under /debug/pprof/),
// built from runtime/pprof + runtime/trace. Exported so callers can mount
// it on an existing admin server instead of using a dedicated listener.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", profileIndex)
	mux.HandleFunc("/debug/pprof/cmdline", cmdline)
	mux.HandleFunc("/debug/pprof/profile", cpuProfile)
	mux.HandleFunc("/debug/pprof/trace", traceProfile)
	return mux
}

// profileIndex lists registered profiles at /debug/pprof/ and serves any
// named runtime/pprof profile (goroutine, heap, threadcreate, allocs,
// block, mutex) at /debug/pprof/<name>. Append ?debug=1 or ?debug=2 for
// the human-readable text form; the default is the protobuf form that
// `go tool pprof` consumes.
func profileIndex(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/debug/pprof/")
	if name == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "available profiles (append ?debug=1 or ?debug=2 for text):")
		for _, p := range pprof.Profiles() {
			fmt.Fprintf(w, "  /debug/pprof/%-13s %d\n", p.Name(), p.Count())
		}
		fmt.Fprintln(w, "  /debug/pprof/profile        CPU profile (?seconds=N)")
		fmt.Fprintln(w, "  /debug/pprof/trace          execution trace (?seconds=N)")
		return
	}
	p := pprof.Lookup(name)
	if p == nil {
		http.Error(w, "unknown profile: "+name, http.StatusNotFound)
		return
	}
	dbg, _ := strconv.Atoi(r.URL.Query().Get("debug"))
	if dbg == 0 {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	_ = p.WriteTo(w, dbg)
}

func cmdline(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, strings.Join(os.Args, "\x00"))
}

func cpuProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	if err := pprof.StartCPUProfile(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer pprof.StopCPUProfile()
	sleep(r, seconds(r, 30))
}

func traceProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	if err := trace.Start(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer trace.Stop()
	sleep(r, seconds(r, 5))
}

// seconds reads ?seconds=N, falling back to def when absent or invalid.
func seconds(r *http.Request, def int) int {
	if s, err := strconv.Atoi(r.URL.Query().Get("seconds")); err == nil && s > 0 {
		return s
	}
	return def
}

// sleep blocks for sec seconds or until the request is cancelled.
func sleep(r *http.Request, sec int) {
	select {
	case <-time.After(time.Duration(sec) * time.Second):
	case <-r.Context().Done():
	}
}

// logRuntimeStats emits goroutine count, OS-thread count (the
// threadcreate profile mirrors the cgroup's pids.current) and heap size
// every interval. A steadily climbing "goroutines" confirms a goroutine
// leak; climbing "os_threads" with flat goroutines points instead at
// threads stuck in blocking syscalls/cgo.
func logRuntimeStats(ctx context.Context, log *slog.Logger, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	threads := pprof.Lookup("threadcreate")
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			log.Info("runtime stats",
				"goroutines", runtime.NumGoroutine(),
				"os_threads", threads.Count(),
				"heap_alloc_mb", ms.HeapAlloc/(1<<20),
			)
		}
	}
}
