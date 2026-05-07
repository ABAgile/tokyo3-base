// Package natsutil provides a small dial helper that composes tlsutil + nats.go
// in the shape three of our internal binaries currently spell out by hand:
//
//	tlsCfg, err := tlsutil.FromFiles(certFile, keyFile, caFile)
//	if err != nil { ... }
//	var opts []nats.Option
//	if tlsCfg != nil { opts = append(opts, nats.Secure(tlsCfg)) }
//	nc, err := nats.Connect(url, opts...)
//
// Dial collapses that into one call. Pass empty cert/key/ca for plaintext
// (development); supply mTLS material for production. Additional nats.Options
// can be layered on (nats.Timeout, nats.DrainTimeout, nats.RetryOnFailedConnect,
// reconnect handlers, …) without bloating the helper's signature — they're
// applied after nats.Secure so the caller's choices win for anything other
// than TLS.
package natsutil

import (
	"github.com/abagile/tokyo3-base/tlsutil"
	"github.com/nats-io/nats.go"
)

// Dial dials a NATS server with optional mTLS. certFile/keyFile/caFile are
// passed to tlsutil.FromFiles — supply all three (or all empty) together;
// when non-nil the resulting TLS config is wired in via nats.Secure ahead of
// any caller-supplied opts.
func Dial(url, certFile, keyFile, caFile string, opts ...nats.Option) (*nats.Conn, error) {
	tlsCfg, err := tlsutil.FromFiles(certFile, keyFile, caFile)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		opts = append([]nats.Option{nats.Secure(tlsCfg)}, opts...)
	}
	return nats.Connect(url, opts...)
}
