package api

import (
	"bytes"
	"errors"
	"log"
	"net/url"
	"strings"
	"testing"
)

func TestRestyLoggerRedactsTransportErrorURLs(t *testing.T) {
	var buf bytes.Buffer
	l := restyLogger{out: log.New(&buf, "", 0), redact: sanitizeURL}
	err := &url.Error{Op: "Get", URL: "http://127.0.0.1:1/x?api_key=SECRETKEY&page=2", Err: errors.New("connection refused")}

	l.Warnf("%v, Attempt %v", err, 1)
	l.Errorf("%v", wrapped{err})

	got := buf.String()
	if strings.Contains(got, "SECRETKEY") {
		t.Fatalf("log leaks the API key: %s", got)
	}
	for _, want := range []string{"WARN RESTY", "ERROR RESTY", "api_key=", "page=2", "connection refused", "Attempt 1"} {
		if !strings.Contains(got, want) {
			t.Errorf("log missing %q: %s", want, got)
		}
	}
}

func TestRestyLoggerRedactsPathParamsForRequest(t *testing.T) {
	var buf bytes.Buffer
	pathParams := map[string]string{"token": "PATHSECRET"}
	l := restyLogger{out: log.New(&buf, "", 0), redact: func(raw string) string {
		return sanitizeRequestURL(raw, pathParams)
	}}
	err := &url.Error{Op: "Get", URL: "http://127.0.0.1:1/reset/PATHSECRET", Err: errors.New("connection refused")}

	l.Warnf("%v, Attempt %v", err, 1)

	if got := buf.String(); strings.Contains(got, "PATHSECRET") {
		t.Fatalf("log leaks the path token: %s", got)
	}
}

func TestRestyLoggerPassesOtherOutputThrough(t *testing.T) {
	var buf bytes.Buffer
	l := restyLogger{out: log.New(&buf, "", 0), redact: sanitizeURL}

	l.Debugf("plain message")
	l.Warnf("status %d %s", 503, "busy")

	want := "DEBUG RESTY plain message\nWARN RESTY status 503 busy\n"
	if got := buf.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

// wrapped hides a *url.Error one level down, as a caller-side wrapper would.
type wrapped struct{ err error }

func (w wrapped) Error() string { return "retry failed: " + w.err.Error() }
func (w wrapped) Unwrap() error { return w.err }
