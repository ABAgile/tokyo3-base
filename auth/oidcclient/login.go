package oidcclient

import (
	"context"
	"errors"
	"io"
)

// LoginOptions controls Login's UX. Defaults: code flow on an
// auto-picked loopback port, prompts to os.Stderr.
type LoginOptions struct {
	// Port is the loopback redirect port for the code flow. Zero
	// picks a free one. Ignored when Device is true.
	Port int
	// Device switches to the RFC 8628 device authorization grant.
	// Required on headless hosts.
	Device bool
	// Stderr receives user-facing prompts ("open this URL", device
	// code instructions). Pass io.Discard to silence them — useful
	// in tests. nil also silences.
	Stderr io.Writer
}

// Login runs the chosen OAuth2 flow, persists Config and Tokens to
// $XDG_CONFIG_HOME/auth-sso/, and returns the Tokens.
//
// Idempotent in the sense that a successful login over-writes any
// previously-cached tokens. A failed OAuth flow leaves the cache untouched.
// Tokens are stored with their issuer/client identity before config.json is
// updated, so a partial persistence failure cannot refresh against the wrong
// issuer. Such a mismatch requires another login.
func Login(ctx context.Context, cfg Config, opt LoginOptions) (*Tokens, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, errors.New("oidcclient.Login: Issuer and ClientID are required")
	}
	var (
		tokens *Tokens
		err    error
	)
	if opt.Device {
		tokens, err = RunDeviceFlow(ctx, cfg.Issuer, cfg.ClientID, opt.Stderr)
	} else {
		tokens, err = RunCodeFlow(ctx, cfg.Issuer, cfg.ClientID, opt.Port, opt.Stderr)
	}
	if err != nil {
		return nil, err
	}
	if err := saveTokens(tokens, &cfg); err != nil {
		return nil, err
	}
	if err := SaveConfig(cfg); err != nil {
		return nil, err
	}
	return tokens, nil
}
