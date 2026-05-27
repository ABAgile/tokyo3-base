package applog

import (
	"fmt"
	"log/slog"
	"time"

	bnats "github.com/abagile/tokyo3-base/nats"
	"github.com/nats-io/nats.go"
)

// Default timing knobs for [NATSConfig]. Picked to match the five
// hand-rolled call-sites this package replaces, except for Timeout
// which moves from 1 s → 5 s: 1 s is tight on multi-AZ deployments
// where the initial DNS + TCP + TLS round-trip can legitimately
// take a second or two. Failure-case cost is the daemon sits a few
// more seconds at boot before falling back to stdout-only.
const (
	DefaultNATSDialTimeout   = 5 * time.Second
	DefaultNATSDrainTimeout  = 2 * time.Second
	DefaultNATSReconnectWait = 2 * time.Second
)

// NATSConfig describes the NATS endpoint used for operational log
// shipping. URL empty disables shipping (the helper emits an Info
// "skipped" line and returns a no-op drain).
//
// CertFile / KeyFile / CAFile are passed straight through to
// [bnats.Dial]. Each binary owns the env-var fallback chain that
// produces these paths — keeping that policy in cmd/ lets daemons
// share their NATS material with the audit pipeline or
// workload-identity store without this package having an opinion.
//
// Timeout / DrainTimeout / ReconnectWait override the defaults
// declared as constants in this file. Leave any field zero to take
// the default.
type NATSConfig struct {
	URL      string // empty disables shipping
	CertFile string
	KeyFile  string
	CAFile   string

	// Timeout caps the initial dial. Zero ⇒ DefaultNATSDialTimeout.
	Timeout time.Duration
	// DrainTimeout caps the graceful drain invoked by the returned
	// callback. Zero ⇒ DefaultNATSDrainTimeout.
	DrainTimeout time.Duration
	// ReconnectWait spaces reconnect attempts after the initial
	// connection is established. Zero ⇒ DefaultNATSReconnectWait.
	ReconnectWait time.Duration
}

// AppLoggerWithNATS combines [AppLogger] with optional async NATS
// log shipping. writers configures sinks (e.g., [WithStdout]) that
// run alongside the NATS writer the helper adds when cfg.URL is
// set. Pass no writers to get NATS-only when URL is set; with both
// writers and URL empty the call collapses to plain [AppLogger].
//
// The NATS connection is dialed with self-healing semantics:
//
//   - RetryOnFailedConnect(true) so a broker that's down at boot
//     doesn't fail logger construction; the connection establishes
//     in the background.
//   - MaxReconnects(-1) + ReconnectWait for indefinite reconnection
//     without operator intervention.
//   - Async writer is discard-on-full (200-entry buffer) so a
//     stalled NATS publish can't apply backpressure on a hot
//     logging path.
//
// Dial-time errors (malformed URL, missing TLS material) are NOT
// fatal — they're logged on the returned logger as a Warn and
// shipping is skipped for the process lifetime. Log shipping is
// observational; failing to enable it must not break startup.
//
// Three startup messages distinguish the outcomes for operators
// grepping "log shipping" in boot logs:
//
//	URL empty   →  INFO "operational log shipping skipped"   reason=no URL configured
//	dial failed →  WARN "operational log shipping skipped"   reason=dial failure  err=<...>
//	dialed      →  INFO "operational log shipping configured" subject=app_log.<app>
//
// The returned [*slog.LevelVar] controls runtime log-level changes
// (same as [AppLogger]). The drain callback flushes the async
// writer and closes the NATS connection; defer it from the caller's
// run loop so SIGTERM doesn't lose buffered entries. drain is
// always safe to call (no-op when shipping is disabled).
func AppLoggerWithNATS(app string, cfg NATSConfig, writers ...WriterOption) (*slog.Logger, *slog.LevelVar, func()) {
	nc, dialErr := dialLogNATS(cfg)
	drain := func() {}
	allWriters := writers
	if nc != nil {
		drain = func() { _ = nc.Drain() }
		allWriters = append(append([]WriterOption(nil), writers...), WithAsyncNats(nc))
	}
	log, lv := AppLogger(app, allWriters...)
	switch {
	case cfg.URL == "":
		log.Info("operational log shipping skipped", "reason", "no URL configured")
	case dialErr != nil:
		log.Warn("operational log shipping skipped", "reason", "dial failure", "err", dialErr)
	default:
		// "configured" rather than "shipping" — RetryOnFailedConnect
		// means the connection may still be establishing in the
		// background; entries get dropped (AsyncWriter is
		// discard-on-full) until it does.
		log.Info("operational log shipping configured", "subject", "app_log."+app)
	}
	return log, lv, drain
}

// dialLogNATS wraps [bnats.Dial] with the timing options that the
// five existing binaries (certd, cert-agentd, authd, ssh-proxyd,
// ssh-tunneld) converged on. Returns (nil, nil) when the URL is
// empty so callers can use the helper unconditionally and skip
// wiring NATS only when configured.
func dialLogNATS(cfg NATSConfig) (*nats.Conn, error) {
	if cfg.URL == "" {
		return nil, nil
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultNATSDialTimeout
	}
	drainTimeout := cfg.DrainTimeout
	if drainTimeout == 0 {
		drainTimeout = DefaultNATSDrainTimeout
	}
	reconnectWait := cfg.ReconnectWait
	if reconnectWait == 0 {
		reconnectWait = DefaultNATSReconnectWait
	}
	nc, err := bnats.Dial(cfg.URL, cfg.CertFile, cfg.KeyFile, cfg.CAFile,
		nats.Timeout(timeout),
		nats.DrainTimeout(drainTimeout),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(reconnectWait),
	)
	if err != nil {
		return nil, fmt.Errorf("log shipping: %w", err)
	}
	return nc, nil
}
