// Package clientip resolves the real client IP from an HTTP request that may
// arrive through trusted reverse proxies, in a way the client cannot spoof.
//
// The immediate TCP peer (r.RemoteAddr) is the only address a client cannot
// forge, so it is the source of truth. X-Forwarded-For is consulted only when
// that peer is itself a configured trusted proxy, in which case the rightmost
// hop that is NOT trusted — the real client as seen by infrastructure we
// control — is returned. Walking the header right-to-left and stopping at the
// first untrusted hop defeats a client that pre-seeds X-Forwarded-For to spoof
// its source. With no trusted proxies configured, X-Forwarded-For is ignored
// entirely and the peer IP is always returned.
//
// This is the shared extraction that both rate-limit keying and audit
// attribution should use, so a single source IP is derived one way across the
// fleet. It applies to HTTP only; an SSH/raw-TCP peer is just net.Addr and has
// no forwarding header to reason about.
package clientip

import (
	"net"
	"net/http"
	"strings"
)

// Extractor resolves the real client IP for requests arriving through a known
// set of trusted reverse proxies. Build it with [New]; the zero value (no
// trusted proxies) is valid and always returns the immediate peer IP.
type Extractor struct {
	trusted []*net.IPNet
}

// New returns an Extractor that trusts the given reverse-proxy CIDRs for
// X-Forwarded-For. Pass nil or empty to ignore X-Forwarded-For entirely — the
// peer IP is then always the client, so the header can't be used to spoof a
// source.
func New(trustedProxies []*net.IPNet) *Extractor {
	return &Extractor{trusted: trustedProxies}
}

// FromRequest returns the real client IP for r as a bare host without a port:
// the immediate TCP peer, or — when that peer is a trusted proxy — the
// rightmost X-Forwarded-For hop that is not itself trusted. When r.RemoteAddr
// carries no port it is returned verbatim.
func (e *Extractor) FromRequest(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)
	if len(e.trusted) == 0 || !e.isTrusted(peer) {
		return peer
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip != "" && !e.isTrusted(ip) {
			return ip
		}
	}
	return peer
}

func (e *Extractor) isTrusted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range e.trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func hostOnly(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
