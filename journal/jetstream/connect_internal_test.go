package jetstream

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
)

// The lifecycle callbacks are the operator's only signal that audit
// publishing is down. They are driven directly here, against a connection
// that never reaches a server, so no broker is needed.
func TestConnectOptions_LifecycleLogsNameTheFace(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	nc, err := nats.Connect("nats://127.0.0.1:1", nats.RetryOnFailedConnect(true))
	if err != nil {
		t.Fatalf("connect with RetryOnFailedConnect: %v", err)
	}
	defer nc.Close()

	opts := nats.GetDefaultOptions()
	for _, apply := range connectOptions(nil, log, 0, "probe") {
		if err := apply(&opts); err != nil {
			t.Fatal(err)
		}
	}
	opts.DisconnectedErrCB(nc, errors.New("link reset"))
	opts.ReconnectedCB(nc)
	opts.ClosedCB(nc)

	out := buf.String()
	for _, want := range []string{"nats disconnected", "link reset", "nats reconnected", "nats connection closed", "face=probe"} {
		if !strings.Contains(out, want) {
			t.Errorf("lifecycle log missing %q:\n%s", want, out)
		}
	}
}

// Without a logger the callbacks are not installed, so a connection with no
// log sink never reaches the logging code at all.
func TestConnectOptions_NoLoggerInstallsNoCallbacks(t *testing.T) {
	opts := nats.GetDefaultOptions()
	for _, apply := range connectOptions(nil, nil, 0, "probe") {
		if err := apply(&opts); err != nil {
			t.Fatal(err)
		}
	}
	if opts.DisconnectedErrCB != nil || opts.ReconnectedCB != nil || opts.ClosedCB != nil {
		t.Error("lifecycle callbacks installed without a logger")
	}
}

// A URL that does not parse is a configuration error and must fail at
// construction, not be deferred to a background retry loop.
func TestNewSinkAndSource_RejectMalformedURL(t *testing.T) {
	if _, err := NewSink(SinkConfig{URL: "://not-a-url", Subject: "events"}); err == nil {
		t.Error("NewSink accepted a malformed URL")
	}
	if _, err := NewSource(SourceConfig{URL: "://not-a-url", StreamName: "s", Subject: "events"}); err == nil {
		t.Error("NewSource accepted a malformed URL")
	}
}
