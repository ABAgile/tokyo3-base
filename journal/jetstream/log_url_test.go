package jetstream

import "testing"

func TestLogURLRemovesUserinfo(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"password", "nats://svc:hunter2@nats.example:4222", "nats://nats.example:4222"},
		{"token only", "tls://s3cr3t-token@nats.example:4222", "tls://nats.example:4222"},
		{"list with credentials in one entry", "nats://a.example:4222,nats://svc:hunter2@b.example:4222", "nats://a.example:4222,nats://b.example:4222"},
		{"no userinfo unchanged", "tls://nats.example:4222", "tls://nats.example:4222"},
		{"unparseable", "nats://\x7f:bad", "[invalid URL]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := logURL(tc.in); got != tc.want {
				t.Fatalf("logURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
