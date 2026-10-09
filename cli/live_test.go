package cli

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/internal/livetest"
	"github.com/abagile/tokyo3-base/journal"
	"github.com/stretchr/testify/require"
)

// The tests in this file wire App.Setup and the audit helpers to a live NATS
// server. They skip unless BASE_TEST_NATS_URL is set (see package livetest).

// TestLiveSetupShipsLogsFromEnv: the NATS URL resolved from <PREFIX>_NATS_URL
// drives log shipping on a live server, to app_log.<Name>.
func TestLiveSetupShipsLogsFromEnv(t *testing.T) {
	url := livetest.NATSURL(t)
	name := livetest.UniqueName(t, "basetest-cli-")
	t.Setenv("BASETESTCLI_NATS_URL", url)
	payloads := livetest.Observe(t, url, "app_log."+name)

	rt := App{Name: name, EnvPrefix: "BASETESTCLI"}.Setup(t.Context())
	t.Cleanup(rt.Shutdown) // idempotent; the explicit call below flushes before we wait
	msg := livetest.UniqueName(t, "setup-")
	rt.Log.Info(msg)
	rt.Shutdown() // drains the shipper, so the entry is on the server

	livetest.AwaitPayload(t, payloads, msg)
}

type cliAuditEntry struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

// TestLiveAuditHelpersUseResolvedNATS: AuditSink and AuditSource, built from
// the material Setup resolved, publish to and read from a live JetStream stream.
func TestLiveAuditHelpersUseResolvedNATS(t *testing.T) {
	url := livetest.NATSURL(t)
	base := livetest.UniqueName(t, "basetest.cliaudit.")
	stream := livetest.UniqueName(t, "basetest_cliaudit_")
	subject := base + ".events"
	livetest.CreateJetStreamStream(t, url, stream, base+".>")
	t.Setenv("BASETESTCLI_NATS_URL", url)

	rt := App{Name: "basetest-cli-audit", EnvPrefix: "BASETESTCLI"}.Setup(t.Context())
	t.Cleanup(rt.Shutdown)

	sink, err := AuditSink[cliAuditEntry](rt, subject, AuditRequired())
	require.NoError(t, err)

	src, err := AuditSource(rt, stream, subject)
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ch, err := src.Subscribe(ctx, 10, 0)
	require.NoError(t, err)

	want := cliAuditEntry{ID: "e-1", Action: "issue"}
	require.NoError(t, sink.Append(ctx, want))

	var msg journal.Msg
	select {
	case msg = <-ch:
	case <-ctx.Done():
		t.Fatal("no audit entry read back from the stream")
	}
	var got cliAuditEntry
	require.NoError(t, json.Unmarshal(msg.Data, &got))
	require.Equal(t, want, got)
}
