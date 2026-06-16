package reloader

import (
	"crypto/tls"
	"fmt"
	"log/slog"

	btls "github.com/abagile/tokyo3-base/tls"
)

// ServerTLSConfig describes the inputs to [ServerTLS].
type ServerTLSConfig struct {
	// CertFile and KeyFile are the server leaf cert/key PEM paths. Both
	// set ⇒ a hot-reloading [CertLoader] serves the cert (mtime-gated, so
	// a rotation lands within ~1s across handshakes). Both empty ⇒ an
	// ephemeral self-signed cert is generated (dev only; a warning is
	// logged). Exactly one set is an error.
	CertFile string
	KeyFile  string

	// ClientCAFile is an optional inbound client-CA bundle. When set, mTLS
	// client verification is wired via [NewClientCALoader] (hot-reloaded:
	// the bundle is re-read mtime-gated, keep-last-good on a bad drop-in).
	// Empty ⇒ client-cert verification stays off.
	ClientCAFile string

	// ClientAuth is applied when ClientCAFile is set. Zero value
	// ([tls.VerifyClientCertIfGiven]) lets route-level handlers decide
	// whether to require a client cert.
	ClientAuth tls.ClientAuthType

	// MinVersion is the minimum TLS version. Zero ⇒ the Go default.
	MinVersion uint16

	// Log receives the cert-source and client-CA hot-reload messages.
	// Required.
	Log *slog.Logger
}

// ServerTLS builds the *tls.Config for an HTTPS listener: a hot-reloading
// server cert (CertFile/KeyFile) or an ephemeral self-signed cert (dev
// fallback when both are empty), plus optional hot-reloading inbound
// client-CA verification (ClientCAFile).
//
// It is the shared implementation behind each daemon's buildServerTLS — the
// callers differ only in env-var names, the workload-CA fallback for the
// client CA, and MinVersion, all of which they resolve before calling.
func ServerTLS(cfg ServerTLSConfig) (*tls.Config, error) {
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, fmt.Errorf("cert and key files must both be set or both unset")
	}

	out := &tls.Config{MinVersion: cfg.MinVersion}
	if cfg.CertFile != "" {
		cfg.Log.Info("tls: using certificate files (hot-reload enabled)", "cert", cfg.CertFile)
		out.GetCertificate = NewCertLoader(cfg.CertFile, cfg.KeyFile).GetCertificate
	} else {
		cfg.Log.Warn("tls: no certificate configured, using self-signed (not for production)")
		cert, err := btls.SelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		out.Certificates = []tls.Certificate{cert}
	}

	if cfg.ClientCAFile != "" {
		auth := cfg.ClientAuth
		if auth == tls.NoClientCert {
			auth = tls.VerifyClientCertIfGiven
		}
		// Hot-reload the inbound client-CA bundle: base wires ClientAuth +
		// ClientCAs + a per-handshake GetConfigForClient so a CA rotation
		// (widen→narrow) lands without a restart, keeping the last good pool
		// on a bad drop-in.
		caLoader, err := NewClientCALoader(out, cfg.ClientCAFile, auth)
		if err != nil {
			return nil, fmt.Errorf("client CA %q: %w", cfg.ClientCAFile, err)
		}
		caLoader.OnError = func(err error) {
			cfg.Log.Warn("tls: client CA hot-reload kept previous pool", "ca", cfg.ClientCAFile, "err", err)
		}
		cfg.Log.Info("tls: mTLS client CA loaded (hot-reload)", "ca", cfg.ClientCAFile)
	}

	return out, nil
}
