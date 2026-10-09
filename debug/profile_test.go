package debug

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime/pprof"
	"runtime/trace"
	"strings"
	"testing"
	"time"
)

// fetch returns the response and body for path, so tests can check headers.
func fetch(t *testing.T, srv *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp, body
}

// gzipMagic opens every protobuf profile, which pprof gzip-compresses.
var gzipMagic = []byte{0x1f, 0x8b}

func TestProfileDefaultFormatIsAttachment(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp, body := fetch(t, srv, "/debug/pprof/goroutine")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, `filename="goroutine"`) {
		t.Errorf("Content-Disposition = %q, want an attachment named goroutine", cd)
	}
	if !bytes.HasPrefix(body, gzipMagic) {
		t.Errorf("body is not a gzip-compressed profile: % x", body[:min(len(body), 4)])
	}
}

func TestIndexListsProfileEndpoints(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	_, body := fetch(t, srv, "/debug/pprof/")
	for _, want := range []string{"goroutine", "heap", "/debug/pprof/profile", "/debug/pprof/trace"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("index does not mention %q:\n%s", want, body)
		}
	}
}

func TestCPUProfileServesGzipProfile(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp, body := fetch(t, srv, "/debug/pprof/profile?seconds=1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %q", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
	if !bytes.HasPrefix(body, gzipMagic) {
		t.Errorf("CPU profile is not gzip-compressed: % x", body[:min(len(body), 4)])
	}
}

// Only one CPU profile can run per process. A second request must fail
// with a 500 rather than block or corrupt the running profile.
func TestCPUProfileRefusesWhileAnotherIsRunning(t *testing.T) {
	var held bytes.Buffer
	if err := pprof.StartCPUProfile(&held); err != nil {
		t.Fatal(err)
	}
	defer pprof.StopCPUProfile()

	srv := httptest.NewServer(Handler())
	defer srv.Close()
	resp, body := fetch(t, srv, "/debug/pprof/profile?seconds=1")
	if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(string(body), "already in use") {
		t.Errorf("status = %d, body %q; want 500 mentioning the profiler is in use", resp.StatusCode, body)
	}
}

func TestTraceServesTraceData(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp, body := fetch(t, srv, "/debug/pprof/trace?seconds=1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %q", resp.StatusCode, body)
	}
	if !bytes.HasPrefix(body, []byte("go ")) || !bytes.Contains(body[:min(len(body), 32)], []byte(" trace")) {
		t.Errorf("body does not start with an execution trace header: %q", body[:min(len(body), 32)])
	}
}

func TestTraceRefusesWhileAnotherIsRunning(t *testing.T) {
	var held bytes.Buffer
	if err := trace.Start(&held); err != nil {
		t.Fatal(err)
	}
	defer trace.Stop()

	srv := httptest.NewServer(Handler())
	defer srv.Close()
	resp, body := fetch(t, srv, "/debug/pprof/trace?seconds=1")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, body %q; want 500 while a trace is running", resp.StatusCode, body)
	}
}

// When the client disconnects, the handler must return early and stop the
// profiler. The deferred Stop is what lets the next profile start.
func TestCPUProfileStopsWhenClientGoesAway(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodGet, "/debug/pprof/profile?seconds=120", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { cpuProfile(w, r); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler kept profiling after the client went away")
	}
	var next bytes.Buffer
	if err := pprof.StartCPUProfile(&next); err != nil {
		t.Fatalf("profiler still held after the client went away: %v", err)
	}
	pprof.StopCPUProfile()
}

func TestTraceStopsWhenClientGoesAway(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodGet, "/debug/pprof/trace?seconds=120", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { traceProfile(w, r); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("trace kept running after the client went away")
	}
	var next bytes.Buffer
	if err := trace.Start(&next); err != nil {
		t.Fatalf("trace still held after the client went away: %v", err)
	}
	trace.Stop()
}

func TestSleepReturnsWhenRequestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	start := time.Now()
	sleep(r, 60)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("sleep ignored the cancelled request for %v", elapsed)
	}
}

func TestSleepWaitsForRequestedDuration(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	start := time.Now()
	sleep(r, 1)
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Errorf("sleep(1s) returned after %v", elapsed)
	}
}
