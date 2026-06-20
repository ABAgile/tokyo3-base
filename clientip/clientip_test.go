package clientip_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abagile/tokyo3-base/clientip"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func req(remoteAddr, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "no trusted proxies ignores XFF",
			remoteAddr: "203.0.113.9:4444",
			xff:        "1.1.1.1",
			want:       "203.0.113.9",
		},
		{
			name:       "untrusted peer ignores XFF",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "203.0.113.9:4444",
			xff:        "1.1.1.1",
			want:       "203.0.113.9",
		},
		{
			name:       "trusted proxy returns rightmost untrusted hop",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.5:4444",
			xff:        "198.51.100.7, 10.0.0.9, 10.0.0.5",
			want:       "198.51.100.7",
		},
		{
			name:       "trusted proxy with single client hop",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.5:4444",
			xff:        "198.51.100.7",
			want:       "198.51.100.7",
		},
		{
			name:       "trusted proxy but empty XFF falls back to peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.5:4444",
			want:       "10.0.0.5",
		},
		{
			name:       "all hops trusted falls back to peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.5:4444",
			xff:        "10.0.0.9, 10.0.0.5",
			want:       "10.0.0.5",
		},
		{
			name:       "remote addr without port returned verbatim",
			remoteAddr: "203.0.113.9",
			want:       "203.0.113.9",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cidrs []*net.IPNet
			for _, c := range tc.trusted {
				cidrs = append(cidrs, mustCIDR(t, c))
			}
			ext := clientip.New(cidrs)
			if got := ext.FromRequest(req(tc.remoteAddr, tc.xff)); got != tc.want {
				t.Errorf("FromRequest = %q, want %q", got, tc.want)
			}
		})
	}
}
