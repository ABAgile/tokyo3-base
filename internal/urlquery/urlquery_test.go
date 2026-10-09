package urlquery

import (
	"net/url"
	"testing"
)

func TestMerge(t *testing.T) {
	params := url.Values{"client_id": {"portal"}, "state": {"s1"}}
	cases := []struct{ name, endpoint, want string }{
		{"no query", "https://idp.example/authorize", "https://idp.example/authorize?client_id=portal&state=s1"},
		{"empty query", "https://idp.example/authorize?", "https://idp.example/authorize?client_id=portal&state=s1"},
		{"keeps endpoint query", "https://idp.example/authorize?tenant=foo", "https://idp.example/authorize?client_id=portal&state=s1&tenant=foo"},
		{"caller overrides endpoint value", "https://idp.example/authorize?client_id=other&tenant=foo", "https://idp.example/authorize?client_id=portal&state=s1&tenant=foo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Merge(tc.endpoint, params)
			if err != nil {
				t.Fatalf("Merge: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Merge(%q) = %q, want %q", tc.endpoint, got, tc.want)
			}
		})
	}
}

func TestMergeRejectsUnparseableEndpoint(t *testing.T) {
	if _, err := Merge("https://idp.example/\x7f", url.Values{}); err == nil {
		t.Fatal("want error for unparseable endpoint")
	}
}
