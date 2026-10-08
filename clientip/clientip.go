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
	"net/netip"
	"slices"
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
// rightmost X-Forwarded-For hop that is not itself trusted. The result is
// canonicalized (IPv4-mapped IPv6 becomes plain IPv4) so one client maps to
// one string; a peer that is not an IP is returned verbatim. All
// X-Forwarded-For header lines are treated as one list; a malformed hop falls
// back to the immediate peer.
func (e *Extractor) FromRequest(r *http.Request) string {
	peer := canonical(hostOnly(r.RemoteAddr))
	if len(e.trusted) == 0 || !e.isTrusted(peer) {
		return peer
	}
	xff := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for _, part := range slices.Backward(parts) {
		ip := strings.TrimSpace(part)
		if net.ParseIP(ip) == nil {
			return peer
		}
		if !e.isTrusted(ip) {
			return canonical(ip)
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

// canonical returns the canonical text form of an IP literal, with an
// IPv4-mapped IPv6 address unmapped to IPv4, or host unchanged if it is not
// an IP.
func canonical(host string) string {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	return addr.Unmap().String()
}

// Network maps a client IP (as returned by [Extractor.FromRequest]) to the
// string that identifies its source network, for anything that counts or
// limits per source: IPv6 addresses collapse to their /64 prefix, IPv4 and
// anything that is not an IP are returned unchanged.
//
// A single IPv6 subscriber is normally delegated a whole /64 (or larger), so
// keying on the exact address lets one client rotate through 2^64 addresses
// and never hit a per-source limit. Keep audit/attribution on the exact
// [Extractor.FromRequest] value; use Network only where grouping is the goal.
func Network(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return ip
	}
	p, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// NetworkKey is [Network] applied to [Extractor.FromRequest]: the per-source
// key for r.
func (e *Extractor) NetworkKey(r *http.Request) string {
	return Network(e.FromRequest(r))
}
