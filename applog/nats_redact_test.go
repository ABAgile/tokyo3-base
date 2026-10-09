package applog

import (
	"bytes"
	"strings"
	"testing"

	plog "github.com/phuslu/log"
)

// A malformed NATS URL fails at dial time, and the failure is logged as the
// startup warning. The password in the URL must not reach that warning.
func TestAppLoggerWithNATS_DialFailureOmitsCredentials(t *testing.T) {
	var buf bytes.Buffer
	AppLoggerWithNATS(Config{App: "test-app"}, NATSConfig{URL: "nats://svc:hunter2@host:bad"}, func(_ Config, ws *[]plog.Writer) {
		*ws = append(*ws, &plog.IOWriter{Writer: &buf})
	})
	out := buf.String()
	if !strings.Contains(out, "operational log shipping skipped") || !strings.Contains(out, "dial failure") {
		t.Fatalf("missing dial-failure warning: %s", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("startup warning leaks credentials: %s", out)
	}
}
