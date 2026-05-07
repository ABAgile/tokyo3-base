// Package jetstream is a NATS JetStream implementation of journal.Sink.
//
// Append publishes synchronously and waits for the JetStream server-ack
// before returning, so the caller observes any publish error and can
// fail the originating operation accordingly (the fail-closed contract).
//
// The stream covering the configured subject must already exist — this
// package does not provision streams. Provision out-of-band (a sidecar
// container running `nats stream add`, an operator-managed stream, or a
// one-shot init job). Decoupling the publisher from stream management
// keeps the publisher's NATS credential PUBLISH-only on the configured
// subject; no stream-management rights are required.
package jetstream

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Config configures a Sink.
type Config struct {
	// URL is the NATS server URL (e.g. "tls://nats:4222"). Required.
	URL string
	// Subject is the NATS subject to publish to. Required. Must be covered
	// by an existing JetStream stream.
	Subject string
	// TLS, when non-nil, enables mTLS on the NATS connection. The server
	// is expected to derive the publisher identity from the cert subject
	// or SPIFFE URI SAN (e.g. via verify_and_map). Leave nil for
	// plaintext (development only).
	TLS *tls.Config
}

// Sink publishes payloads to NATS JetStream synchronously. Implements
// journal.Sink (defined in the parent package).
type Sink struct {
	nc      *nats.Conn
	js      jetstream.JetStream
	subject string
}

// New dials NATS and returns a ready Sink. Returns an error if the
// connection cannot be established or required configuration is missing.
// The caller owns the Sink's lifetime and must call Close on shutdown.
func New(cfg Config) (*Sink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("url required")
	}
	if cfg.Subject == "" {
		return nil, fmt.Errorf("subject required")
	}
	var opts []nats.Option
	if cfg.TLS != nil {
		opts = append(opts, nats.Secure(cfg.TLS))
	}
	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream client: %w", err)
	}
	return &Sink{nc: nc, js: js, subject: cfg.Subject}, nil
}

// Append publishes payload to the configured subject and waits for the
// JetStream server-ack. Returns the publish error on failure; callers
// rely on this to fail the originating operation (fail-closed).
func (s *Sink) Append(ctx context.Context, payload []byte) error {
	if _, err := s.js.Publish(ctx, s.subject, payload); err != nil {
		return fmt.Errorf("jetstream publish: %w", err)
	}
	return nil
}

// Close drains the NATS connection, flushing any in-flight messages
// before tearing down the underlying TCP connection.
func (s *Sink) Close() error {
	return s.nc.Drain()
}
