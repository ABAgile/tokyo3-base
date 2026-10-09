package clientip_test

import (
	"net"
	"testing"

	"github.com/abagile/tokyo3-base/clientip"
)

// Only an IP literal can be a trusted proxy. A peer that is not an IP must be
// refused whatever the trust list says, so even a trust list covering every
// address cannot be used to forge a client IP.
func TestIsTrustedPeer_NonIPPeerIsNeverTrusted(t *testing.T) {
	e := clientip.New([]*net.IPNet{mustCIDR(t, "0.0.0.0/0"), mustCIDR(t, "::/0")})
	for _, remote := range []string{"garbage:80", "unix-socket", ""} {
		if e.IsTrustedPeer(req(remote, "203.0.113.9")) {
			t.Errorf("RemoteAddr %q treated as a trusted proxy", remote)
		}
		if got := e.FromRequest(req(remote, "203.0.113.9")); got == "203.0.113.9" {
			t.Errorf("RemoteAddr %q let X-Forwarded-For set the client IP to %q", remote, got)
		}
	}
	// Control: a real IP in the same range is trusted.
	if !e.IsTrustedPeer(req("203.0.113.1:80", "")) {
		t.Error("control: an IPv4 peer inside the trust list should be trusted")
	}
}

// A proxy that connects over IPv6 as an IPv4-mapped address matches the IPv4
// trust range. The client IP it reports must be the plain IPv4 form, so one
// client maps to one string whichever way it connected.
func TestIsTrustedPeer_IPv4MappedAddressesAreCanonical(t *testing.T) {
	e := clientip.New([]*net.IPNet{mustCIDR(t, "10.0.0.0/8")})
	if !e.IsTrustedPeer(req("[::ffff:10.0.0.5]:80", "")) {
		t.Error("IPv4-mapped 10.0.0.5 should match the 10.0.0.0/8 trust range")
	}
	if e.IsTrustedPeer(req("[::ffff:203.0.113.9]:80", "")) {
		t.Error("IPv4-mapped address outside the trust range was trusted")
	}
	if got := e.FromRequest(req("[::ffff:10.0.0.5]:80", "")); got != "10.0.0.5" {
		t.Errorf("trusted mapped peer reported as %q, want 10.0.0.5", got)
	}
	if got := e.FromRequest(req("[::ffff:10.0.0.5]:80", "::ffff:203.0.113.9")); got != "203.0.113.9" {
		t.Errorf("forwarded mapped client reported as %q, want 203.0.113.9", got)
	}
}
