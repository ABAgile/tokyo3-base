// Package jetstream is a NATS JetStream implementation of journal.Sink and
// journal.Source — the write face publishes synchronously and waits for the
// JetStream server-ack before returning, the read face attaches an ephemeral
// ack-none consumer with a configurable backfill window and tails forward.
//
// Sink and Source are independent — pick whichever face the caller needs;
// they share no state and own their own NATS connection. The stream
// covering the configured subject must already exist for both — this
// package does not provision streams. Provision out-of-band (a sidecar
// container running `nats stream add`, an operator-managed stream, or a
// one-shot init job). Decoupling the publisher from stream management
// keeps publishing credentials PUBLISH-only and reading credentials
// CONSUME-only on the configured subject; no stream-management rights are
// required by either face.
package jetstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/abagile/tokyo3-base/journal"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// ── Sink (write face) ─────────────────────────────────────────────────────────

// SinkConfig configures a Sink. The publisher needs only a subject; the
// stream that covers that subject must be pre-provisioned.
type SinkConfig struct {
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

// NewSink dials NATS and returns a ready Sink. Returns an error if the
// connection cannot be established or required configuration is missing.
// The caller owns the Sink's lifetime and must call Close on shutdown.
func NewSink(cfg SinkConfig) (*Sink, error) {
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

// ── Source (read face) ────────────────────────────────────────────────────────

// SourceConfig configures a Source. Distinct from SinkConfig: a reader has
// to know which stream to attach the ephemeral consumer to, whereas the
// publisher only knows the subject.
type SourceConfig struct {
	// URL is the NATS server URL (e.g. "tls://nats:4222"). Required.
	URL string
	// StreamName is the JetStream stream this Source reads from. Required.
	// The stream must already exist; the Source does not provision it.
	StreamName string
	// Subject is set as the consumer's FilterSubject so a multi-subject
	// stream can be tailed selectively. Use the same subject the producer
	// publishes to. Required.
	Subject string
	// TLS, when non-nil, enables mTLS on the NATS connection. Leave nil
	// for plaintext (development only).
	TLS *tls.Config
	// InactiveThreshold is how long an ephemeral consumer can sit idle
	// before JetStream deletes it. Default 5 minutes — long enough for a
	// browser SSE reconnect with Last-Event-ID, short enough that abandoned
	// consumers don't accumulate. Set explicitly to override.
	InactiveThreshold time.Duration
}

// Source reads from NATS JetStream as a journal.Source. One Source per
// stream-subject pair; concurrent Subscribe calls each create their own
// ephemeral consumer on the shared NATS connection.
type Source struct {
	nc                *nats.Conn
	js                jetstream.JetStream
	stream            jetstream.Stream
	subject           string
	inactiveThreshold time.Duration
}

// NewSource dials NATS, looks up the stream, and returns a ready Source.
// Returns an error if the connection cannot be established, the stream does
// not exist, or required configuration is missing.
func NewSource(cfg SourceConfig) (*Source, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("url required")
	}
	if cfg.StreamName == "" {
		return nil, fmt.Errorf("stream name required")
	}
	if cfg.Subject == "" {
		return nil, fmt.Errorf("subject required")
	}
	inactive := cfg.InactiveThreshold
	if inactive <= 0 {
		inactive = 5 * time.Minute
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
	stream, err := js.Stream(context.Background(), cfg.StreamName)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream stream %q: %w", cfg.StreamName, err)
	}
	return &Source{
		nc:                nc,
		js:                js,
		stream:            stream,
		subject:           cfg.Subject,
		inactiveThreshold: inactive,
	}, nil
}

// Subscribe creates an ephemeral, ack-none consumer with a delivery policy
// chosen to satisfy the requested backfill window:
//
//   - startFromSeq > 0:        ByStartSequence(startFromSeq)         (resume)
//   - replay <= 0 OR empty:    New                                   (tail only)
//   - replay >= stream length: All                                   (whole stream)
//   - otherwise:               ByStartSequence(LastSeq - replay + 1) (last N)
//
// Returns a channel that delivers messages in publish order until ctx is
// cancelled. The channel closes when the inner iterator stops (server
// disconnect, ctx cancel, or InactiveThreshold expiry on the server side).
func (s *Source) Subscribe(ctx context.Context, replay int, startFromSeq uint64) (<-chan journal.Msg, error) {
	info, err := s.stream.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("stream info: %w", err)
	}
	policy, optStart := pickDeliverPolicy(replay, startFromSeq, info.State.LastSeq)
	cons, err := s.stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		FilterSubject:     s.subject,
		AckPolicy:         jetstream.AckNonePolicy,
		DeliverPolicy:     policy,
		OptStartSeq:       optStart,
		InactiveThreshold: s.inactiveThreshold,
	})
	if err != nil {
		return nil, fmt.Errorf("create ephemeral consumer: %w", err)
	}
	mc, err := cons.Messages()
	if err != nil {
		return nil, fmt.Errorf("open messages iterator: %w", err)
	}
	// Stop the iterator when the caller cancels: Next() blocks otherwise.
	// Stop() unblocks Next() with ErrMsgIteratorClosed; the loop returns
	// and closes the output channel cleanly.
	go func() {
		<-ctx.Done()
		mc.Stop()
	}()

	ch := make(chan journal.Msg)
	go func() {
		defer close(ch)
		for {
			msg, err := mc.Next()
			if err != nil {
				if errors.Is(err, jetstream.ErrMsgIteratorClosed) {
					return
				}
				// Any other error (connection drop, server gone): the
				// caller's ctx will likely fire shortly; either way the
				// iterator is dead.
				return
			}
			meta, mErr := msg.Metadata()
			if mErr != nil {
				continue
			}
			out := journal.Msg{
				Seq:  meta.Sequence.Stream,
				Time: meta.Timestamp,
				Data: msg.Data(),
			}
			select {
			case <-ctx.Done():
				return
			case ch <- out:
			}
		}
	}()
	return ch, nil
}

// Close drains the NATS connection. Outstanding Subscribe channels close
// shortly after, as their iterator returns.
func (s *Source) Close() error {
	return s.nc.Drain()
}

// pickDeliverPolicy is the start-policy decision tree, factored out for
// testing without a live JetStream.
func pickDeliverPolicy(replay int, startFromSeq, lastSeq uint64) (jetstream.DeliverPolicy, uint64) {
	if startFromSeq > 0 {
		return jetstream.DeliverByStartSequencePolicy, startFromSeq
	}
	if replay <= 0 || lastSeq == 0 {
		return jetstream.DeliverNewPolicy, 0
	}
	if uint64(replay) >= lastSeq {
		return jetstream.DeliverAllPolicy, 0
	}
	return jetstream.DeliverByStartSequencePolicy, lastSeq - uint64(replay) + 1
}
