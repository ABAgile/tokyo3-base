// Package livetest gates and provisions tests that need a live PostgreSQL or
// NATS server. Each live test skips unless its variable is set, so the default
// `go test ./...` stays hermetic:
//
//	BASE_TEST_DATABASE_URL  postgres:// URL, with a password when the server requires one, e.g. postgres://postgres:secret@postgres:5432/postgres?sslmode=disable
//	BASE_TEST_NATS_URL      nats:// URL of a server with JetStream enabled, e.g. nats://nats:4222
//
// The server may be shared, so tests create only uniquely named resources
// (see [UniqueName]) and remove what they create.
package livetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	envDatabaseURL = "BASE_TEST_DATABASE_URL"
	envNATSURL     = "BASE_TEST_NATS_URL"
)

// PostgresDSN returns the postgres:// URL from BASE_TEST_DATABASE_URL, skipping
// tb when unset.
func PostgresDSN(tb testing.TB) string {
	tb.Helper()
	dsn := strings.TrimSpace(os.Getenv(envDatabaseURL))
	if dsn == "" {
		tb.Skipf("set %s to run against a live PostgreSQL server", envDatabaseURL)
	}
	return dsn
}

// NATSURL returns the URL from BASE_TEST_NATS_URL, skipping tb when unset.
func NATSURL(tb testing.TB) string {
	tb.Helper()
	url := strings.TrimSpace(os.Getenv(envNATSURL))
	if url == "" {
		tb.Skipf("set %s to run against a live NATS server with JetStream", envNATSURL)
	}
	return url
}

// UniqueName returns prefix followed by 8 random hex digits, so parallel runs
// and leftovers from earlier runs never collide.
func UniqueName(tb testing.TB, prefix string) string {
	tb.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		tb.Fatalf("random name: %v", err)
	}
	return prefix + hex.EncodeToString(b[:])
}

// Observe subscribes to subject on a fresh connection to the server at url and
// returns a channel of received payloads. It returns only after the server has
// registered the subscription, so anything published afterwards is seen. The
// connection is closed when tb finishes.
func Observe(tb testing.TB, url, subject string) <-chan []byte {
	tb.Helper()
	nc, err := nats.Connect(url, nats.Timeout(5*time.Second))
	if err != nil {
		tb.Fatalf("connect %s: %v", url, err)
	}
	tb.Cleanup(nc.Close)
	out := make(chan []byte, 256)
	sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
		select {
		case out <- m.Data:
		default: // buffer full: drop rather than stall the NATS delivery goroutine
		}
	})
	if err != nil {
		tb.Fatalf("subscribe %s: %v", subject, err)
	}
	tb.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		tb.Fatalf("flush subscription: %v", err)
	}
	return out
}

// AwaitPayload returns the first payload on ch containing needle, failing tb
// after 10 seconds.
func AwaitPayload(tb testing.TB, ch <-chan []byte, needle string) []byte {
	tb.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case p := <-ch:
			if bytes.Contains(p, []byte(needle)) {
				return p
			}
		case <-timeout:
			tb.Fatalf("no payload containing %q within 10s", needle)
		}
	}
}

// CreateJetStreamStream creates an in-memory stream called name covering
// subjects on the server at url, and deletes it when tb finishes. The
// journal/jetstream packages never provision streams, so tests create them
// here through the management API.
func CreateJetStreamStream(tb testing.TB, url, name string, subjects ...string) {
	tb.Helper()
	nc, err := nats.Connect(url, nats.Timeout(5*time.Second))
	if err != nil {
		tb.Fatalf("connect %s: %v", url, err)
	}
	tb.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		tb.Fatalf("jetstream client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name:     name,
		Subjects: subjects,
		Storage:  jetstream.MemoryStorage,
	}); err != nil {
		tb.Fatalf("create stream %s: %v", name, err)
	}
	// Registered after nc.Close, so it runs first (LIFO) while the connection
	// is still open.
	tb.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := js.DeleteStream(ctx, name); err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
			tb.Errorf("delete stream %s: %v", name, err)
		}
	})
}
