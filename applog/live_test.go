package applog

import (
	"testing"

	"github.com/abagile/tokyo3-base/internal/livetest"
)

// TestLiveAppLoggerShipsToSubject: entries logged through AppLoggerWithNATS
// reach the app_log subject on a live server, with the instance suffix when
// one is configured. Runs only when BASE_TEST_NATS_URL is set.
func TestLiveAppLoggerShipsToSubject(t *testing.T) {
	url := livetest.NATSURL(t)
	app := livetest.UniqueName(t, "basetest-app-")
	cases := []struct {
		name     string
		instance string
		subject  string
	}{
		{"app subject", "", "app_log." + app},
		{"instance subject", "host-7", "app_log." + app + ".host-7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payloads := livetest.Observe(t, url, tc.subject)
			logger, _, drain := AppLoggerWithNATS(
				Config{App: app, Instance: tc.instance},
				NATSConfig{URL: url},
			)
			msg := livetest.UniqueName(t, "shipped-")
			logger.Info(msg, "key", "value")
			// drain flushes the async writer and the connection, so the entry is on the server.
			drain()
			livetest.AwaitPayload(t, payloads, msg)
		})
	}
}
