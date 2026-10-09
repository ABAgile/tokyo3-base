package applog

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/phuslu/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A logger derived with WithGroup must write its attributes under the group,
// and must still follow the level control of the logger it came from.
func TestAppLogger_GroupedLoggerKeepsOutputAndLevel(t *testing.T) {
	var buf bytes.Buffer
	capture := func(_ Config, ws *[]log.Writer) { *ws = append(*ws, &log.IOWriter{Writer: &buf}) }
	logger, lv := AppLogger(Config{App: "myapp"}, capture)

	grouped := logger.WithGroup("req")
	grouped.Info("hit", "path", "/roles")
	out := buf.String()
	if !strings.Contains(out, "req") || !strings.Contains(out, "/roles") {
		t.Fatalf("grouped attribute missing from output: %q", out)
	}

	lv.Set(slog.LevelWarn)
	assert.False(t, grouped.Enabled(context.Background(), slog.LevelInfo), "level change must reach derived loggers")
	buf.Reset()
	grouped.Info("suppressed")
	assert.Empty(t, buf.String(), "info line written after raising the level")
}

// A publish that fails must surface to the caller as an error with no bytes
// counted as written, so the logging layer can see the entry was lost.
func TestNatsWriter_WriteReportsPublishFailure(t *testing.T) {
	nc, err := nats.Connect("nats://127.0.0.1:1", nats.RetryOnFailedConnect(true))
	require.NoError(t, err)
	nc.Close()

	nw := &NatsWriter{Nc: nc, Subject: "app_log.test"}
	n, err := nw.Write([]byte("entry\n"))
	assert.Error(t, err, "publish on a closed connection must fail")
	assert.Zero(t, n, "a failed publish must not report bytes written")
}
