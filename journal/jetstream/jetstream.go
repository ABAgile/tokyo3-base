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
	"log/slog"
	"sync"
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
	// Log, when set, receives structured connection-lifecycle events
	// (disconnect, reconnect, closed). Useful in production where the
	// connection retries in the background and operators want a
	// log/alert surface for sustained broker outage. Nil ⇒ events are
	// silently swallowed (the NATS client still retries).
	Log *slog.Logger
	// ReconnectWait is the delay between reconnect attempts. 0 ⇒
	// [DefaultReconnectWait].
	ReconnectWait time.Duration
}

// DefaultReconnectWait is the gap between reconnect attempts the
// underlying NATS client uses when SinkConfig.ReconnectWait is zero.
// Picked to mirror the NATS client's own default and to avoid
// flooding a recovering broker.
const DefaultReconnectWait = 2 * time.Second

// Sink publishes payloads to NATS JetStream synchronously. Implements
// journal.Sink (defined in the parent package).
type Sink struct {
	nc      *nats.Conn
	js      jetstream.JetStream
	subject string
}

// NewSink returns a ready Sink. NATS dial failures do NOT cause an
// error here — the underlying client retries the connection in the
// background ([DefaultReconnectWait] between attempts, unbounded) so
// the caller's bootstrap is not gated on broker reachability.
// Configuration shape errors (empty URL/Subject) still return
// synchronously. The caller owns the Sink's lifetime and must call
// Close on shutdown.
//
// Connection-lifecycle events are logged through SinkConfig.Log when
// set; sustained "disconnected" state is the operator's signal that
// audit publishing is currently unavailable.
func NewSink(cfg SinkConfig) (*Sink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("url required")
	}
	if cfg.Subject == "" {
		return nil, fmt.Errorf("subject required")
	}
	opts := connectOptions(cfg.TLS, cfg.Log, cfg.ReconnectWait, "jetstream-sink")
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

// connectOptions builds the nats.Option list every face here uses.
// Centralised so Sink and Source share retry semantics without
// drifting. The "face" arg surfaces in lifecycle logs so operators
// can tell which connection an event came from.
func connectOptions(tlsCfg *tls.Config, log *slog.Logger, reconnectWait time.Duration, face string) []nats.Option {
	if reconnectWait <= 0 {
		reconnectWait = DefaultReconnectWait
	}
	opts := []nats.Option{
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(reconnectWait),
	}
	if tlsCfg != nil {
		opts = append(opts, nats.Secure(tlsCfg))
	}
	if log != nil {
		opts = append(opts,
			nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
				log.Warn("nats disconnected", "face", face, "err", err)
			}),
			nats.ReconnectHandler(func(nc *nats.Conn) {
				log.Info("nats reconnected", "face", face, "url", nc.ConnectedUrl())
			}),
			nats.ClosedHandler(func(_ *nats.Conn) {
				log.Warn("nats connection closed", "face", face)
			}),
		)
	}
	return opts
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
	// Log, when set, receives structured connection-lifecycle events
	// (disconnect, reconnect, closed). Symmetric with SinkConfig.Log.
	Log *slog.Logger
	// ReconnectWait is the delay between reconnect attempts. 0 ⇒
	// [DefaultReconnectWait].
	ReconnectWait time.Duration
}

// Source reads from NATS JetStream as a journal.Source. One Source per
// stream-subject pair; concurrent Subscribe calls each create their own
// ephemeral consumer on the shared NATS connection.
//
// Stream lookup is deferred to the first [Source.Subscribe] call so
// constructing a Source does not block on broker reachability. A
// missing stream surfaces as a Subscribe error, not as a fatal
// startup error — the caller decides whether to retry.
type Source struct {
	nc                *nats.Conn
	js                jetstream.JetStream
	streamName        string
	subject           string
	inactiveThreshold time.Duration
	log               *slog.Logger

	streamMu sync.Mutex
	stream   jetstream.Stream
}

// NewSource returns a ready Source. NATS dial failures do NOT cause
// an error here — the underlying client retries the connection in
// the background ([DefaultReconnectWait] between attempts, unbounded)
// so the caller's bootstrap is not gated on broker reachability. The
// JetStream stream lookup is deferred to the first
// [Source.Subscribe] call; "stream not found" therefore surfaces
// there rather than at construction.
//
// Configuration shape errors (empty URL/StreamName/Subject) still
// return synchronously.
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
	opts := connectOptions(cfg.TLS, cfg.Log, cfg.ReconnectWait, "jetstream-source")
	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream client: %w", err)
	}
	return &Source{
		nc:                nc,
		js:                js,
		streamName:        cfg.StreamName,
		subject:           cfg.Subject,
		inactiveThreshold: inactive,
		log:               cfg.Log,
	}, nil
}

// ensureStream resolves the configured JetStream stream the first time
// it's called (memoised under streamMu). Subsequent calls return the
// cached handle. Failures are not memoised — a transient broker
// outage on the first Subscribe self-heals when Subscribe is called
// again after the connection recovers.
func (s *Source) ensureStream(ctx context.Context) (jetstream.Stream, error) {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if s.stream != nil {
		return s.stream, nil
	}
	stream, err := s.js.Stream(ctx, s.streamName)
	if err != nil {
		return nil, fmt.Errorf("jetstream stream %q: %w", s.streamName, err)
	}
	s.stream = stream
	return stream, nil
}

// Subscribe creates an ephemeral, ack-none consumer with a delivery policy
// chosen to satisfy the requested backfill window:
//
//   - startFromSeq in 1..LastSeq+1: ByStartSequence(startFromSeq)    (resume; a
//     value past the stream end is treated as a reset and ignored)
//   - replay <= 0 OR empty:    New                                   (tail only)
//   - replay >= stream length: All                                   (whole stream)
//   - otherwise:               ByStartSequence(LastSeq - replay + 1) (last N)
//
// Returns a channel that delivers messages in publish order until ctx is
// cancelled. The channel closes when the inner iterator stops (server
// disconnect, ctx cancel, or InactiveThreshold expiry on the server side).
func (s *Source) Subscribe(ctx context.Context, replay int, startFromSeq uint64) (<-chan journal.Msg, error) {
	stream, err := s.ensureStream(ctx)
	if err != nil {
		return nil, err
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("stream info: %w", err)
	}
	policy, optStart := pickDeliverPolicy(replay, startFromSeq, info.State.LastSeq)
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		FilterSubject:     s.subject,
		AckPolicy:         jetstream.AckNonePolicy,
		DeliverPolicy:     policy,
		OptStartSeq:       optStart,
		InactiveThreshold: s.inactiveThreshold,
	})
	if err != nil {
		return nil, fmt.Errorf("create ephemeral consumer: %w", err)
	}
	// The consumer is ephemeral but outlives its iterator until the server's
	// InactiveThreshold lapses, so delete it ourselves once the subscription
	// ends — otherwise every (re)connect leaves one behind for minutes.
	consumerName := cons.CachedInfo().Name
	mc, err := cons.Messages()
	if err != nil {
		releaseConsumer(ctx, stream, consumerName, s.log)
		return nil, fmt.Errorf("open messages iterator: %w", err)
	}
	// Stop the iterator when the caller cancels: Next() blocks otherwise.
	// Stop() unblocks Next() with ErrMsgIteratorClosed; the loop returns
	// and closes the output channel cleanly.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-done: // reader exited on its own; don't linger until ctx ends
		}
		mc.Stop()
	}()

	ch := make(chan journal.Msg)
	go func() {
		// Deferred first so it runs last: the consumer is deleted after the
		// iterator has stopped and the channel has closed, so a slow broker
		// delays only this goroutine, not the caller.
		defer func() {
			mc.Stop()
			releaseConsumer(ctx, stream, consumerName, s.log)
		}()
		defer close(ch)
		defer close(done)
		for {
			msg, err := mc.Next()
			if err != nil {
				if errors.Is(err, jetstream.ErrMsgIteratorClosed) {
					return
				}
				// Any other error (connection drop, server gone): the
				// caller's ctx will likely fire shortly; either way the
				// iterator is dead. Say so, or the closed channel looks like
				// a clean end of stream.
				if s.log != nil && ctx.Err() == nil {
					s.log.Warn("jetstream subscription ended", "stream", s.streamName, "subject", s.subject, "err", err)
				}
				return
			}
			out, err := decodeMsg(msg)
			if err != nil {
				// AckNone leaves nothing to redeliver, so the gap is visible only here.
				if s.log != nil {
					s.log.Warn("jetstream message dropped: unreadable metadata", "stream", s.streamName, "subject", s.subject, "err", err)
				}
				continue
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

// releaseConsumerTimeout bounds the best-effort consumer cleanup.
const releaseConsumerTimeout = 5 * time.Second

// consumerDeleter is the part of jetstream.Stream releaseConsumer needs.
type consumerDeleter interface {
	DeleteConsumer(ctx context.Context, consumer string) error
}

// releaseConsumer deletes the ephemeral consumer behind a finished
// subscription. It runs detached from ctx — normally already cancelled by the
// time the subscription ends — under its own timeout. Failure is only logged:
// the server's InactiveThreshold reaps the consumer eventually.
func releaseConsumer(ctx context.Context, stream consumerDeleter, name string, log *slog.Logger) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseConsumerTimeout)
	defer cancel()
	if err := stream.DeleteConsumer(dctx, name); err != nil && !errors.Is(err, jetstream.ErrConsumerNotFound) && log != nil {
		log.Warn("jetstream consumer cleanup failed; it expires after InactiveThreshold", "consumer", name, "err", err)
	}
}

// Close drains the NATS connection. Outstanding Subscribe channels close
// shortly after, as their iterator returns.
func (s *Source) Close() error {
	return s.nc.Drain()
}

// decodeMsg converts a JetStream message to a journal.Msg. It fails when the
// metadata, and so the stream sequence, cannot be read.
func decodeMsg(m jetstream.Msg) (journal.Msg, error) {
	meta, err := m.Metadata()
	if err != nil {
		return journal.Msg{}, err
	}
	return journal.Msg{Seq: meta.Sequence.Stream, Time: meta.Timestamp, Data: m.Data()}, nil
}

// pickDeliverPolicy is the start-policy decision tree, factored out for
// testing without a live JetStream.
func pickDeliverPolicy(replay int, startFromSeq, lastSeq uint64) (jetstream.DeliverPolicy, uint64) {
	// A resume point past the stream's end (lastSeq+1 is the next message) means
	// the stream was reset or recreated since the caller last saw it; waiting
	// for sequences to catch up would deliver nothing, so fall back to replay.
	if startFromSeq > 0 && startFromSeq <= lastSeq+1 {
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
