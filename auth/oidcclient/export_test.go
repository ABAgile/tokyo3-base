package oidcclient

import (
	"sync"
	"testing"
	"time"
)

// deviceSleeperMu serializes UseInstantDeviceSleeper installations so
// concurrent tests can't see a half-installed swap. Same pattern the
// codeflow internal tests use for the openBrowser var.
var deviceSleeperMu sync.Mutex

// UseInstantDeviceSleeper replaces the device-flow polling sleeper
// with one that fires after a millisecond, then restores the original
// on t.Cleanup. Reduces device-flow tests from ~1–3 s each (gated by
// the RFC 8628 minimum 1 s poll interval) to milliseconds while still
// giving the runtime an explicit scheduler yield between iterations.
//
// Exported via the export_test.go convention so the external
// package-level test file (deviceflow_test.go in package
// oidcclient_test) can use it without leaking the seam onto the
// production API.
func UseInstantDeviceSleeper(t testing.TB) {
	t.Helper()
	deviceSleeperMu.Lock()
	original := deviceSleeper
	deviceSleeper = func(_ time.Duration) <-chan time.Time {
		return time.After(time.Millisecond)
	}
	t.Cleanup(func() {
		deviceSleeper = original
		deviceSleeperMu.Unlock()
	})
}
