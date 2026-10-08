package clientip_test

import (
	"net"
	"testing"

	"github.com/abagile/tokyo3-base/clientip"
)

func TestFromRequest_MultipleForwardedHeaders(t *testing.T) {
	ext := clientip.New([]*net.IPNet{mustCIDR(t, "10.0.0.0/8")})
	r := req("10.0.0.5:4444", "6.6.6.6")                     // client-supplied first line
	r.Header.Add("X-Forwarded-For", "203.0.113.9, 10.0.0.9") // appended by infrastructure
	if got := ext.FromRequest(r); got != "203.0.113.9" {
		t.Fatalf("FromRequest = %q, want real client 203.0.113.9", got)
	}
}

func TestFromRequest_MalformedForwardedHop(t *testing.T) {
	ext := clientip.New([]*net.IPNet{mustCIDR(t, "10.0.0.0/8")})
	for _, xff := range []string{
		"not-an-ip, 10.0.0.9",
		"203.0.113.9, invalid, 10.0.0.9",
		"203.0.113.9, , 10.0.0.9",
		"203.0.113.9:1234, 10.0.0.9",
	} {
		t.Run(xff, func(t *testing.T) {
			if got := ext.FromRequest(req("10.0.0.5:4444", xff)); got != "10.0.0.5" {
				t.Fatalf("malformed header returned %q, want peer 10.0.0.5", got)
			}
		})
	}
}

func TestFromRequest_UntrustedPeerIgnoresMultipleHeaders(t *testing.T) {
	ext := clientip.New([]*net.IPNet{mustCIDR(t, "10.0.0.0/8")})
	r := req("203.0.113.9:4444", "6.6.6.6")
	r.Header.Add("X-Forwarded-For", "7.7.7.7")
	if got := ext.FromRequest(r); got != "203.0.113.9" {
		t.Fatalf("FromRequest = %q, want peer 203.0.113.9", got)
	}
}

func TestFromRequest_Canonicalizes(t *testing.T) {
	e := clientip.New([]*net.IPNet{mustCIDR(t, "10.0.0.0/8")})
	if got := e.FromRequest(req("[::ffff:203.0.113.9]:80", "")); got != "203.0.113.9" {
		t.Errorf("mapped peer = %q, want 203.0.113.9", got)
	}
	if got := e.FromRequest(req("10.0.0.5:80", "::ffff:198.51.100.7")); got != "198.51.100.7" {
		t.Errorf("mapped XFF hop = %q, want 198.51.100.7", got)
	}
	if got := e.FromRequest(req("10.0.0.5:80", "2001:0db8:0:0:0:0:0:1")); got != "2001:db8::1" {
		t.Errorf("XFF hop = %q, want 2001:db8::1", got)
	}
}

func TestNetwork(t *testing.T) {
	tests := []struct{ in, want string }{
		{"203.0.113.9", "203.0.113.9"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, tt := range tests {
		if got := clientip.Network(tt.in); got != tt.want {
			t.Errorf("Network(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNetworkKey_UsesTrustedProxyClient(t *testing.T) {
	e := clientip.New([]*net.IPNet{mustCIDR(t, "10.0.0.0/8")})
	if got := e.NetworkKey(req("10.0.0.5:80", "2001:db8:1:2::9")); got != "2001:db8:1:2::/64" {
		t.Errorf("NetworkKey = %q, want 2001:db8:1:2::/64", got)
	}
}
