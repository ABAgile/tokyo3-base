// Package cli composes the startup boilerplate every tokyo3 daemon
// repeats: an application logger (with optional NATS log shipping), a
// context cancelled on SIGINT/SIGTERM, and the opt-in diagnostics
// server.
//
// It depends on applog, debug, and envutil but deliberately NOT on a
// command framework — each binary keeps its own cobra (or other)
// command tree and calls [App.Setup] from inside its serve command.
// Setup is additive: a daemon with non-standard env keys can skip it
// and wire the pieces directly.
//
// # WORKLOAD identity convention
//
// A daemon's mTLS identity on the platform mesh is <PREFIX>_WORKLOAD_CERT
// / _WORKLOAD_KEY / _WORKLOAD_CA. NATS connections reuse it: each of the
// <PREFIX>_NATS_CERT/KEY/CA keys falls back to the matching WORKLOAD_* so
// a daemon that already has a workload identity ships logs (and audit)
// over mTLS without a second set of env vars. Set <PREFIX>_NATS_* only to
// override NATS with a distinct identity.
//
// [AuditSink] and [AuditSource] build a daemon's primary audit publisher
// and reader from that resolved material, so the common case is a single
// generic call sharing the logger's connection identity. A daemon that
// also reads other streams (e.g. certd tailing ssh-proxy's audit) wires
// those directly — subject, stream, and any extra sources stay
// app-specific.
//
// # Postgres material
//
// [App.DB] and [App.AdminDB] resolve a daemon's Postgres connection
// material — the DSN plus the client mTLS files — into the [DB] struct
// ([Runtime] carries both). The fallback is deliberately split from the
// NATS convention: the client cert/key are a DATABASE-ROLE credential, not
// the workload identity, so <PREFIX>_DB_CERT/KEY do NOT fall back to
// WORKLOAD_* (unset ⇒ no client cert, the DSN's sslmode governs TLS). The
// CA is the shared mesh trust root, so <PREFIX>_DB_CA DOES fall back to
// <PREFIX>_WORKLOAD_CA. [App.AdminDB] adds an ADMIN_* tier for a separate
// DDL credential, each field falling back to the runtime DB value first.
//
// These resolve material only — building a *tls.Config (via
// tls/reloader.ClientConfig) and opening the pool stay caller-side, since
// there is no single Postgres-open layer across the suite.
package cli

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/abagile/tokyo3-base/applog"
	"github.com/abagile/tokyo3-base/debug"
	"github.com/abagile/tokyo3-base/envutil"
	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/jetstream"
)

// App identifies a daemon for startup wiring.
type App struct {
	// Name is the binary's short name (e.g. "certd"). Surfaces as the
	// slog "app" attribute and the app_log NATS subject. Required.
	Name string
	// EnvPrefix is the binary's env-var prefix (e.g. "CERTD"). The
	// standard <PREFIX>_NATS_URL/CERT/KEY/CA, <PREFIX>_WORKLOAD_CERT/KEY/CA
	// (the NATS mTLS fallback), and <PREFIX>_DEBUG_ADDR keys are derived
	// from it. Required.
	EnvPrefix string
	// Instance is an optional per-host identifier for fleet daemons
	// (cert-agentd, ssh-tunneld); when set, ops logs ship to
	// app_log.<Name>.<Instance>. Leave empty for singletons. Callers
	// that want a hostname default can pass
	// envutil.Or(PREFIX+"_INSTANCE", host).
	Instance string
}

// NATS is the resolved NATS connection material: the broker URL plus the
// mTLS files, with cert/key/CA each falling back to the binary's
// WORKLOAD_* identity when a NATS-specific override isn't set.
type NATS struct {
	URL      string
	CertFile string
	KeyFile  string
	CAFile   string
}

// NATS resolves the daemon's NATS material from the environment:
// <PREFIX>_NATS_URL, and <PREFIX>_NATS_CERT/KEY/CA each falling back to
// <PREFIX>_WORKLOAD_CERT/KEY/CA. Safe to call independently of [App.Setup]
// — e.g. to wire an audit sink/source from the same source of truth.
func (a App) NATS() NATS {
	p := a.EnvPrefix
	return NATS{
		URL:      os.Getenv(p + "_NATS_URL"),
		CertFile: envutil.First(p+"_NATS_CERT", p+"_WORKLOAD_CERT"),
		KeyFile:  envutil.First(p+"_NATS_KEY", p+"_WORKLOAD_KEY"),
		CAFile:   envutil.First(p+"_NATS_CA", p+"_WORKLOAD_CA"),
	}
}

// DB is resolved Postgres connection material: the DSN plus the mTLS files.
type DB struct {
	URL      string
	CertFile string
	KeyFile  string
	CAFile   string
}

// DB resolves the daemon's runtime Postgres material: the DSN from
// <PREFIX>_DATABASE_URL and the client mTLS files from <PREFIX>_DB_CERT/KEY/CA.
// The fallback is split (see the package doc): the client cert/key are a
// database-role credential, so they do NOT borrow the WORKLOAD_* identity —
// an unset cert/key means "no client cert" (the DSN's sslmode governs TLS).
// The CA is the shared mesh trust root, so CAFile falls back to
// <PREFIX>_WORKLOAD_CA. Safe to call independently of [App.Setup].
//
// This resolves material only — it does not build a *tls.Config or open a
// connection. The caller turns CertFile/KeyFile/CAFile into a hot-reloading
// config via tls/reloader.ClientConfig (and owns pool tuning and migrations).
func (a App) DB() DB {
	p := a.EnvPrefix
	return DB{
		URL:      os.Getenv(p + "_DATABASE_URL"),
		CertFile: os.Getenv(p + "_DB_CERT"),
		KeyFile:  os.Getenv(p + "_DB_KEY"),
		CAFile:   envutil.First(p+"_DB_CA", p+"_WORKLOAD_CA"),
	}
}

// AdminDB resolves material for a privileged "admin" connection used for
// schema migrations (DDL), for daemons that separate that role from their
// runtime (DML) credential. Each field falls back to the runtime DB value
// first: <PREFIX>_ADMIN_DATABASE_URL → <PREFIX>_DATABASE_URL, and
// <PREFIX>_ADMIN_DB_CERT/KEY → <PREFIX>_DB_CERT/KEY (no WORKLOAD_* — an unset
// cert/key pair means no client cert). The CA continues the shared-root chain
// <PREFIX>_ADMIN_DB_CA → <PREFIX>_DB_CA → <PREFIX>_WORKLOAD_CA. A single-role
// daemon leaves the ADMIN_* vars unset and AdminDB mirrors DB.
func (a App) AdminDB() DB {
	p := a.EnvPrefix
	return DB{
		URL:      envutil.First(p+"_ADMIN_DATABASE_URL", p+"_DATABASE_URL"),
		CertFile: envutil.First(p+"_ADMIN_DB_CERT", p+"_DB_CERT"),
		KeyFile:  envutil.First(p+"_ADMIN_DB_KEY", p+"_DB_KEY"),
		CAFile:   envutil.First(p+"_ADMIN_DB_CA", p+"_DB_CA", p+"_WORKLOAD_CA"),
	}
}

// Runtime is what [App.Setup] returns: a configured logger, a context
// cancelled on SIGINT/SIGTERM (or when the parent cancels), the resolved
// NATS / Postgres material, and a Shutdown to defer.
type Runtime struct {
	Log  *slog.Logger
	Ctx  context.Context
	NATS NATS
	// DB and AdminDB carry the resolved Postgres material (see [App.DB] and
	// [App.AdminDB]). AdminDB mirrors DB unless the ADMIN_* vars are set.
	DB      DB
	AdminDB DB
	// EnvPrefix echoes App.EnvPrefix so the audit helpers (and any
	// bespoke NATS wiring) can derive <PREFIX>_NATS-keyed labels.
	EnvPrefix string
	Shutdown  func()
}

// Setup performs the standard daemon bootstrap:
//
//   - builds the app logger, shipping operational logs to NATS when
//     <PREFIX>_NATS_URL is set (subject app_log.<Name>[.<Instance>]),
//     authenticating with the resolved [App.NATS] material
//   - derives a context cancelled on SIGINT/SIGTERM from parent
//   - starts the diagnostics server when <PREFIX>_DEBUG_ADDR is set
//
// The resolved NATS material is returned in Runtime.NATS so callers can
// wire audit sink/source and other NATS clients from it. Defer the
// returned Runtime.Shutdown to release the signal hook and drain the
// logger.
func (a App) Setup(parent context.Context) Runtime {
	n := a.NATS()
	log, _, drainLog := applog.AppLoggerWithNATS(
		applog.Config{App: a.Name, Instance: a.Instance},
		applog.NATSConfig{
			URL:      n.URL,
			CertFile: n.CertFile,
			KeyFile:  n.KeyFile,
			CAFile:   n.CAFile,
		},
		applog.WithStdout(),
	)

	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)

	debug.Start(ctx, debug.Config{Addr: os.Getenv(a.EnvPrefix + "_DEBUG_ADDR"), Log: log})

	return Runtime{
		Log:       log,
		Ctx:       ctx,
		NATS:      n,
		DB:        a.DB(),
		AdminDB:   a.AdminDB(),
		EnvPrefix: a.EnvPrefix,
		Shutdown: func() {
			stop()
			drainLog()
		},
	}
}

// AuditSink builds the daemon's primary audit publisher, encoding the
// app's Entry type T, from the resolved NATS material in rt — so it
// shares the logger's connection identity and the WORKLOAD_* fallback.
// subject is the app's audit subject (e.g. "ca.audit.events"). With no
// NATS URL configured it returns a no-op sink (dev/no-broker path).
func AuditSink[T any](rt Runtime, subject string) (*journal.EncodedSink[T], error) {
	return jetstream.NewAuditSink[T](jetstream.AuditSinkConfig{
		URL:       rt.NATS.URL,
		CertFile:  rt.NATS.CertFile,
		KeyFile:   rt.NATS.KeyFile,
		CAFile:    rt.NATS.CAFile,
		Subject:   subject,
		EnvPrefix: rt.EnvPrefix + "_NATS",
		Log:       rt.Log,
	})
}

// AuditSource builds a reader for the daemon's own audit stream from the
// same resolved NATS material. A daemon reading additional streams (a
// different broker, prefix, or stream) wires those directly. With no
// NATS URL configured it returns a no-op source.
func AuditSource(rt Runtime, stream, subject string) (journal.Source, error) {
	return jetstream.NewAuditSource(jetstream.AuditSourceConfig{
		URL:        rt.NATS.URL,
		CertFile:   rt.NATS.CertFile,
		KeyFile:    rt.NATS.KeyFile,
		CAFile:     rt.NATS.CAFile,
		StreamName: stream,
		Subject:    subject,
		EnvPrefix:  rt.EnvPrefix + "_NATS",
		Log:        rt.Log,
	})
}
