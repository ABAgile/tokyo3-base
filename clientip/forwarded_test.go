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
