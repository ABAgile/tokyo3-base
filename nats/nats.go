// Package nats provides a small dial helper that composes base/tls + nats.go
// in the shape three of our internal binaries currently spell out by hand:
//
//	tlsCfg, err := tls.FromFiles(certFile, keyFile, caFile)
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
package nats

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/abagile/tokyo3-base/tls"
	"github.com/nats-io/nats.go"
)

// Dial dials a NATS server with optional mTLS. certFile/keyFile/caFile are
// passed to tls.FromFiles — supply all three (or all empty) together;
// when non-nil the resulting TLS config is wired in via nats.Secure ahead of
// any caller-supplied opts. Connect errors are returned through [RedactError].
func Dial(url, certFile, keyFile, caFile string, opts ...nats.Option) (*nats.Conn, error) {
	tlsCfg, err := tls.FromFiles(certFile, keyFile, caFile)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		opts = append([]nats.Option{nats.Secure(tlsCfg)}, opts...)
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, RedactError(err)
	}
	return nc, nil
}

// RedactURL returns raw with any userinfo (passwords, tokens) removed, so NATS
// connection URLs can be logged. nats.go accepts a comma-separated server
// list, so each entry is redacted separately. An entry without "://" is
// redacted as nats.go reads it (nats://<entry>) and keeps its scheme-less
// form. An entry that does not parse, or has no authority to redact from, is
// replaced by "[invalid URL]", since its userinfo cannot be told apart from the
// rest of it.
func RedactURL(raw string) string {
	servers := strings.Split(raw, ",")
	for i, s := range servers {
		servers[i] = redactServer(strings.TrimSpace(s))
	}
	return strings.Join(servers, ",")
}

// redactServer redacts a single entry of a server list. See [RedactURL].
func redactServer(s string) string {
	bare := !strings.Contains(s, "://")
	if bare {
		s = "nats://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" {
		return "[invalid URL]"
	}
	u.User = nil
	if bare {
		return strings.TrimPrefix(u.String(), "nats://")
	}
	return u.String()
}

// RedactError returns err with the credentials removed from the connection URL
// it reports. nats.go returns a malformed URL as a *[url.Error] that holds the
// URL as given, userinfo included, and its message repeats that URL. The error
// is created by the failed call and not shared, so its URL field is rewritten
// in place. Wrappers such as fmt.Errorf cache their message, so the text they
// add is rewritten as well, and the original error stays in the chain for
// errors.Is and errors.As.
func RedactError(err error) error {
	ue, ok := errors.AsType[*url.Error](err)
	if !ok {
		return err
	}
	raw := ue.URL
	ue.URL = RedactURL(raw)
	msg := err.Error()
	redacted := strings.NewReplacer(strconv.Quote(raw), strconv.Quote(ue.URL), raw, ue.URL).Replace(msg)
	if redacted == msg {
		return err
	}
	return &redactedError{msg: redacted, err: err}
}

// redactedError has a sanitized message and unwraps to the original error.
type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }
