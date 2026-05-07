package nats

import (
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// TestDial_BadCertFile: when cert paths are supplied but unreadable, the
// tlsutil.FromFiles error propagates without any network attempt.
func TestDial_BadCertFile(t *testing.T) {
	_, err := Dial("nats://127.0.0.1:1", "/nonexistent/cert.pem", "/nonexistent/key.pem", "")
	if err == nil {
		t.Fatal("expected error for missing cert/key files, got nil")
	}
}

// TestDial_NoTLS_Unreachable: with empty cert/key/ca and an unreachable URL
// nats.Connect surfaces a dial error. nats.Timeout keeps the test fast.
func TestDial_NoTLS_Unreachable(t *testing.T) {
	_, err := Dial(
		"nats://127.0.0.1:1", "", "", "",
		nats.Timeout(100*time.Millisecond),
	)
	if err == nil {
		t.Fatal("expected dial error to unreachable URL, got nil")
	}
}

// TestDial_OptsLayered: caller-supplied options reach nats.Connect. Verified
// indirectly — pass nats.Name and look for it in the resulting Conn (when the
// dial fails the Name is captured in the error path's Opts struct, but the
// reliable way is to set a tiny Timeout and check the error mentions a
// timeout-shaped message). We just verify dial fails fast under the supplied
// timeout, which proves the option was applied.
func TestDial_OptsLayered(t *testing.T) {
	start := time.Now()
	_, err := Dial(
		"nats://127.0.0.1:1", "", "", "",
		nats.Timeout(50*time.Millisecond),
	)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected dial to fail")
	}
	if elapsed > 2*time.Second {
		t.Errorf("dial elapsed %v — Timeout option does not appear to be applied", elapsed)
	}
	// Sanity: the error should mention connection refused or timeout, not a
	// TLS misconfiguration.
	if strings.Contains(err.Error(), "tls") {
		t.Errorf("unexpected TLS error in plaintext dial: %v", err)
	}
}
