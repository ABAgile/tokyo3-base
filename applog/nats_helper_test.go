package applog

import (
	"strings"
	"testing"
	"time"
)

// TestAppLoggerWithNATS_EmptyURL_StdoutOnly: the no-NATS path is the
// fallback every dev/test deployment hits. URL empty ⇒ stdout-only
// logger (via the caller-supplied WithStdout()), drain is callable
// without panicking and the "skipped (no URL configured)" Info line
// surfaces so operators see the state.
func TestAppLoggerWithNATS_EmptyURL_StdoutOnly(t *testing.T) {
	log, lv, drain := AppLoggerWithNATS("test-app", NATSConfig{}, WithStdout())
	if log == nil {
		t.Fatal("logger is nil")
	}
	if lv == nil {
		t.Fatal("level var is nil")
	}
	if drain == nil {
		t.Fatal("drain is nil — must be a no-op closure, never nil")
	}
	// Must be safe to call repeatedly.
	drain()
	drain()
}

// TestAppLoggerWithNATS_NoWriters_FallsBackToAppLoggerDefault: the
// helper composes — passing zero writers + empty URL should still
// produce a usable logger, since [AppLogger] falls back to stdout
// when its writer list is empty.
func TestAppLoggerWithNATS_NoWriters_FallsBackToAppLoggerDefault(t *testing.T) {
	log, _, drain := AppLoggerWithNATS("test-app", NATSConfig{})
	if log == nil {
		t.Fatal("logger is nil — AppLogger fallback should have kicked in")
	}
	log.Info("hello")
	drain()
}

// TestDialLogNATS_EmptyURL_SkipsDial verifies the URL-empty fast
// path returns (nil, nil) — used by AppLoggerWithNATS to recognise
// "no shipping configured" without trying to dial.
func TestDialLogNATS_EmptyURL_SkipsDial(t *testing.T) {
	nc, err := dialLogNATS(NATSConfig{})
	if err != nil {
		t.Fatalf("dialLogNATS(empty) err = %v, want nil", err)
	}
	if nc != nil {
		t.Fatalf("dialLogNATS(empty) nc = %v, want nil", nc)
	}
}

// TestDialLogNATS_MalformedURL_ReturnsError exercises the
// dial-failure surface. nats.Connect rejects malformed URLs at
// parse time, before RetryOnFailedConnect kicks in.
func TestDialLogNATS_MalformedURL_ReturnsError(t *testing.T) {
	nc, err := dialLogNATS(NATSConfig{URL: "://not-a-url"})
	if err == nil {
		t.Fatalf("dialLogNATS(malformed) err = nil, want error; nc=%v", nc)
	}
	if nc != nil {
		t.Fatalf("dialLogNATS on failure returned non-nil conn: %v", nc)
	}
	if !strings.Contains(err.Error(), "log shipping") {
		t.Errorf("err = %q, want prefix 'log shipping'", err.Error())
	}
}

// TestAppLoggerWithNATS_MalformedURL_FailsClosed: a malformed URL
// must NOT prevent construction — log shipping is observational, so
// a config typo can't take down the daemon. The logger is still
// usable, drain is still callable.
func TestAppLoggerWithNATS_MalformedURL_FailsClosed(t *testing.T) {
	log, _, drain := AppLoggerWithNATS("test-app", NATSConfig{URL: "://not-a-url"}, WithStdout())
	if log == nil {
		t.Fatal("logger is nil on dial failure — must fall back to stdout")
	}
	// Logger must remain usable. If this panicked we'd see it here.
	log.Info("hello after dial failure")
	drain()
}

// TestDialLogNATS_UnreachableURL_RetriesInBackground: with
// RetryOnFailedConnect(true), an unreachable broker still yields a
// non-error conn (queued for background reconnect). The helper
// must accept that and wire drain accordingly.
func TestDialLogNATS_UnreachableURL_RetriesInBackground(t *testing.T) {
	// 127.0.0.1:1 is reserved and reliably refused on every platform
	// we run on. Combined with nats.Timeout the test caps at ~5s.
	nc, err := dialLogNATS(NATSConfig{URL: "nats://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("dialLogNATS with RetryOnFailedConnect should not error on initial unreachable broker: %v", err)
	}
	if nc == nil {
		t.Fatal("nc is nil — expected a conn queued for reconnect")
	}
	// Defer-style cleanup. Drain on an unconnected conn is a no-op,
	// but calling it must not panic.
	_ = nc.Drain()
	nc.Close()
}

// TestDialLogNATS_AppliesCustomTimeout: when cfg.Timeout is set,
// the helper hands it to nats.Timeout. Exercises the "explicit
// value beats default" branch; we can't easily observe the actual
// timeout from nats.go, so we just confirm the dial succeeds with
// a custom value (proves the path doesn't reject non-zero input).
func TestDialLogNATS_AppliesCustomTimeout(t *testing.T) {
	nc, err := dialLogNATS(NATSConfig{
		URL:           "nats://127.0.0.1:1",
		Timeout:       500 * time.Millisecond,
		DrainTimeout:  100 * time.Millisecond,
		ReconnectWait: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("dialLogNATS with custom timing should not error on unreachable broker (RetryOnFailedConnect): %v", err)
	}
	if nc == nil {
		t.Fatal("nc is nil — expected a conn queued for reconnect")
	}
	_ = nc.Drain()
	nc.Close()
}
