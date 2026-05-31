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
)

// App identifies a daemon for startup wiring.
type App struct {
	// Name is the binary's short name (e.g. "certd"). Surfaces as the
	// slog "app" attribute and the app_log NATS subject. Required.
	Name string
	// EnvPrefix is the binary's env-var prefix (e.g. "CERTD"). The
	// standard <PREFIX>_NATS_URL/CERT/KEY/CA and <PREFIX>_DEBUG_ADDR
	// keys are derived from it. Required.
	EnvPrefix string
	// Instance is an optional per-host identifier for fleet daemons
	// (cert-agentd, ssh-tunneld); when set, ops logs ship to
	// app_log.<Name>.<Instance>. Leave empty for singletons. Callers
	// that want a hostname default can pass
	// envutil.Or(PREFIX+"_INSTANCE", host).
	Instance string
}

// Runtime is what [App.Setup] returns: a configured logger, a context
// cancelled on SIGINT/SIGTERM (or when the parent cancels), and a
// Shutdown to defer.
type Runtime struct {
	Log      *slog.Logger
	Ctx      context.Context
	Shutdown func()
}

// Setup performs the standard daemon bootstrap:
//
//   - builds the app logger, shipping operational logs to NATS when
//     <PREFIX>_NATS_URL is set (subject app_log.<Name>[.<Instance>])
//   - derives a context cancelled on SIGINT/SIGTERM from parent
//   - starts the diagnostics server when <PREFIX>_DEBUG_ADDR is set
//
// Defer the returned Runtime.Shutdown to release the signal hook and
// drain the logger.
func (a App) Setup(parent context.Context) Runtime {
	p := a.EnvPrefix
	log, _, drainLog := applog.AppLoggerWithNATS(
		applog.Config{App: a.Name, Instance: a.Instance},
		applog.NATSConfig{
			URL:      os.Getenv(p + "_NATS_URL"),
			CertFile: os.Getenv(p + "_NATS_CERT"),
			KeyFile:  os.Getenv(p + "_NATS_KEY"),
			CAFile:   envutil.First(p+"_NATS_CA", p+"_WORKLOAD_CA"),
		},
		applog.WithStdout(),
	)

	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)

	debug.Start(ctx, debug.Config{Addr: os.Getenv(p + "_DEBUG_ADDR"), Log: log})

	return Runtime{
		Log: log,
		Ctx: ctx,
		Shutdown: func() {
			stop()
			drainLog()
		},
	}
}
