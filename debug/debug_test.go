package debug

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func get(t *testing.T, srv *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestHandlerProfiles(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	if code, body := get(t, srv, "/debug/pprof/"); code != http.StatusOK || !strings.Contains(body, "goroutine") {
		t.Fatalf("index: code=%d body=%q", code, body)
	}
	if code, body := get(t, srv, "/debug/pprof/goroutine?debug=1"); code != http.StatusOK || !strings.Contains(body, "goroutine profile") {
		t.Fatalf("goroutine: code=%d body=%q", code, body)
	}
	if code, _ := get(t, srv, "/debug/pprof/threadcreate?debug=1"); code != http.StatusOK {
		t.Fatalf("threadcreate: code=%d", code)
	}
	if code, _ := get(t, srv, "/debug/pprof/heap?debug=1"); code != http.StatusOK {
		t.Fatalf("heap: code=%d", code)
	}
	if code, _ := get(t, srv, "/debug/pprof/nope"); code != http.StatusNotFound {
		t.Fatalf("unknown profile: want 404, got %d", code)
	}
	if code, body := get(t, srv, "/debug/pprof/cmdline"); code != http.StatusOK || body == "" {
		t.Fatalf("cmdline: code=%d body=%q", code, body)
	}
}

func TestStartNoopWhenAddrEmpty(t *testing.T) {
	// Empty Addr must return immediately and start no listener/goroutines.
	Start(context.Background(), Config{Addr: ""})
}

func TestLogRuntimeStatsEmits(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { logRuntimeStats(ctx, log, 5*time.Millisecond); close(done) }()
	time.Sleep(40 * time.Millisecond)
	cancel()
	<-done
	out := buf.String()
	if !strings.Contains(out, "runtime stats") || !strings.Contains(out, "goroutines=") {
		t.Fatalf("expected a runtime stats line with goroutines, got: %q", out)
	}
}
