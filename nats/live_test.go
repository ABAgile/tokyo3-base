package nats

import (
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/internal/livetest"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"
)

// TestLiveDialRoundTrip: a plaintext Dial to a live server publishes and
// receives, and caller-supplied options reach the connection. Runs only when
// BASE_TEST_NATS_URL is set.
func TestLiveDialRoundTrip(t *testing.T) {
	url := livetest.NATSURL(t)
	nc, err := Dial(url, "", "", "", nats.Name("base-live-test"), nats.Timeout(5*time.Second))
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	require.Equal(t, "base-live-test", nc.Opts.Name, "caller option not applied to the connection")

	subject := livetest.UniqueName(t, "basetest.nats.")
	sub, err := nc.SubscribeSync(subject)
	require.NoError(t, err)
	require.NoError(t, nc.Publish(subject, []byte("ping")))
	require.NoError(t, nc.Flush())

	msg, err := sub.NextMsg(5 * time.Second)
	require.NoError(t, err)
	require.Equal(t, "ping", string(msg.Data))
}
