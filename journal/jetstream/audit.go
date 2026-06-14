package jetstream

import (
	"crypto/tls"
	"fmt"
	"log/slog"

	"github.com/abagile/tokyo3-base/journal"
	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/abagile/tokyo3-base/tls/reloader"
)

// AuditSinkConfig configures [NewAuditSink]. URL empty disables
// publishing (the returned sink wraps [journal.NoopSink] — every
// Append silently drops; safe in dev / no-broker environments).
//
// EnvPrefix appears in the no-op-startup warn and the missing-mTLS
// warn so operators reading the daemon's boot log see exactly which
// env-var family controls audit publishing (e.g. "CERTD_NATS" yields
// "CERTD_NATS_URL not set — audit sink is no-op; not for production").
// Required.
//
// CertFile / KeyFile / CAFile name the connection's TLS material.
// With a full cert+key pair the leaf is reloaded from disk on every
// handshake and the CA pool re-read on mtime change (via
// [reloader.ClientConfig], matching the log shipper), so a
// cert-agentd rotation of the short-TTL workload cert — or of the CA
// bundle — is picked up on the next reconnect without a daemon
// restart; CA-only falls back to one-shot server-auth TLS via
// [btls.FromFiles]. Each binary owns the env-var fallback chain that
// produces these paths — keeping that policy in cmd/ lets daemons
// share NATS material with other transports without this package
// having an opinion.
type AuditSinkConfig struct {
	URL       string
	CertFile  string
	KeyFile   string
	CAFile    string
	Subject   string
	EnvPrefix string
	Log       *slog.Logger
}

// NewAuditSink builds a JSON-encoded JetStream sink for audit
// entries of type T. The encoding is fixed at json.Marshal — matches
// every existing audit pipeline in the suite; non-JSON formats
// should compose [NewSink] + [journal.NewEncodedSink] directly.
//
// Logging contract (mirrors what cmd/main.go binaries spelled out by
// hand before this helper):
//
//   - URL empty:    warn  "<EnvPrefix>_URL not set — audit sink is no-op; not for production"
//   - mTLS active:  info  "audit sink: NATS JetStream with mTLS" url=<URL>
//   - mTLS absent:  warn  "audit sink: <EnvPrefix>_CERT not set — connecting without mTLS (not for production)"
//
// Returns an error only on TLS-material parse failure or [NewSink]
// errors (empty URL/Subject); broker reachability is decoupled from
// startup via NewSink's lazy-connect semantics.
func NewAuditSink[T any](cfg AuditSinkConfig) (*journal.EncodedSink[T], error) {
	if cfg.EnvPrefix == "" {
		return nil, fmt.Errorf("EnvPrefix required")
	}
	if cfg.URL == "" {
		if cfg.Log != nil {
			cfg.Log.Warn(cfg.EnvPrefix + "_URL not set — audit sink is no-op; not for production")
		}
		return journal.NewJSONSink[T](journal.NoopSink{}), nil
	}
	tlsCfg, err := auditTLS(cfg.CertFile, cfg.KeyFile, cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("nats audit TLS: %w", err)
	}
	if cfg.Log != nil {
		if tlsCfg != nil {
			cfg.Log.Info("audit sink: NATS JetStream with mTLS", "url", cfg.URL)
		} else {
			cfg.Log.Warn("audit sink: " + cfg.EnvPrefix + "_CERT not set — connecting without mTLS (not for production)")
		}
	}
	jSink, err := NewSink(SinkConfig{
		URL: cfg.URL, Subject: cfg.Subject, TLS: tlsCfg, Log: cfg.Log,
	})
	if err != nil {
		return nil, err
	}
	return journal.NewJSONSink[T](jSink), nil
}

// AuditSourceConfig configures [NewAuditSource]. URL empty disables
// reads (the returned source is [journal.NoopSource] — Subscribe
// closes its channel immediately on ctx cancel without ever yielding
// a message). The downstream UI then renders empty, matching the
// no-broker dev story on the publish side.
//
// EnvPrefix appears in the no-op-startup warn so operators see which
// env-var family controls audit reads. Required.
//
// Subject is the JetStream subject to attach to; StreamName is the
// stream that covers that subject (jetstream.NewSource doesn't
// provision streams).
type AuditSourceConfig struct {
	URL        string
	CertFile   string
	KeyFile    string
	CAFile     string
	StreamName string
	Subject    string
	EnvPrefix  string
	Log        *slog.Logger
}

// NewAuditSource builds a JetStream-backed [journal.Source] for the
// audit subject. The return type is the generic [journal.Source];
// downstream code typically wraps it in [journal.NewEncodedSource]
// or [journal.NewJSONSource] for typed reads.
//
// Logging contract:
//
//   - URL empty: warn  "<EnvPrefix>_URL not set — audit source is no-op; admin audit page will be empty"
//
// Returns an error only on TLS-material parse failure or [NewSource]
// errors (empty URL / StreamName / Subject); broker reachability is
// decoupled from startup via NewSource's lazy-connect semantics.
func NewAuditSource(cfg AuditSourceConfig) (journal.Source, error) {
	if cfg.EnvPrefix == "" {
		return nil, fmt.Errorf("EnvPrefix required")
	}
	if cfg.URL == "" {
		if cfg.Log != nil {
			cfg.Log.Warn(cfg.EnvPrefix + "_URL not set — audit source is no-op; admin audit page will be empty")
		}
		return journal.NoopSource{}, nil
	}
	tlsCfg, err := auditTLS(cfg.CertFile, cfg.KeyFile, cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("nats audit source TLS: %w", err)
	}
	return NewSource(SourceConfig{
		URL: cfg.URL, StreamName: cfg.StreamName, Subject: cfg.Subject,
		TLS: tlsCfg, Log: cfg.Log,
	})
}

// auditTLS builds the NATS connection's TLS config. A full cert+key
// pair gets a config whose leaf is reloaded from disk on every
// handshake and whose CA pool is re-read on mtime change — the same
// contract dialLogNATS gives the log shipper — so both channels
// survive in-place rotation of the workload cert and the CA bundle.
// Anything short of a pair falls through to one-shot
// [btls.FromFiles]: server-auth TLS when only CAFile is set, nil
// (plaintext) when no material is configured, and the mismatched
// cert-without-key cases keep FromFiles' fail-closed errors.
func auditTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile != "" && keyFile != "" {
		return reloader.ClientConfig(certFile, keyFile, caFile)
	}
	return btls.FromFiles(certFile, keyFile, caFile)
}
