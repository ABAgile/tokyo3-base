package nats

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
)

func TestRedactURLRemovesUserinfo(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"password", "nats://svc:hunter2@nats.example:4222", "nats://nats.example:4222"},
		{"token only", "tls://s3cr3t-token@nats.example:4222", "tls://nats.example:4222"},
		{"list with credentials in one entry", "nats://a.example:4222,nats://svc:hunter2@b.example:4222", "nats://a.example:4222,nats://b.example:4222"},
		{"no userinfo unchanged", "tls://nats.example:4222", "tls://nats.example:4222"},
		{"scheme-less password", "svc:hunter2@nats.example:4222", "nats.example:4222"},
		{"scheme-less list", "a.example:4222,svc:hunter2@b.example:4222", "a.example:4222,b.example:4222"},
		{"scheme-less no userinfo unchanged", "nats.example:4222", "nats.example:4222"},
		{"scheme separator inside password", "svc:hun://ter2@nats.example:4222", "[invalid URL]"},
		{"unparseable", "nats://\x7f:bad", "[invalid URL]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactURL(tc.in); got != tc.want {
				t.Fatalf("RedactURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// nats.go reports a malformed URL as a *url.Error that holds the URL as given.
// The password must not survive in the message, and the error must still
// unwrap to the *url.Error.
func TestDialErrorOmitsCredentials(t *testing.T) {
	cases := []struct{ name, in string }{
		{"single entry", "nats://svc:hunter2@host:bad"},
		{"malformed entry in a list", "nats://a.example:4222,nats://svc:hunter2@host:bad"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Dial(tc.in, "", "", "")
			if err == nil {
				t.Fatal("Dial accepted a malformed URL")
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("error leaks credentials: %v", err)
			}
			ue, ok := errors.AsType[*url.Error](err)
			if !ok {
				t.Fatalf("error chain lost *url.Error: %v", err)
			}
			if strings.Contains(ue.URL, "hunter2") {
				t.Fatalf("url.Error.URL leaks credentials: %q", ue.URL)
			}
		})
	}
}

// A caller that wraps the dial error keeps the raw URL in the wrapper's cached
// message. RedactError must sanitize that text too, and the chain must still
// unwrap to the original *url.Error.
func TestRedactErrorSanitizesWrappedMessage(t *testing.T) {
	cases := []struct{ name, in string }{
		{"single entry", "nats://svc:hunter2@host:bad"},
		{"malformed entry in a list", "nats://a.example:4222,nats://svc:hunter2@host:bad"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, cause := nats.Connect(tc.in)
			if cause == nil {
				t.Fatal("nats.Connect accepted a malformed URL")
			}
			wrapped := fmt.Errorf("connect: %w", cause)
			got := RedactError(wrapped)
			if strings.Contains(got.Error(), "hunter2") {
				t.Fatalf("wrapped error leaks credentials: %v", got)
			}
			if !strings.HasPrefix(got.Error(), "connect: ") {
				t.Fatalf("wrapper context lost: %v", got)
			}
			ue, ok := errors.AsType[*url.Error](got)
			if !ok {
				t.Fatalf("error chain lost *url.Error: %v", got)
			}
			if strings.Contains(ue.URL, "hunter2") {
				t.Fatalf("url.Error.URL leaks credentials: %q", ue.URL)
			}
			if !errors.Is(got, cause) {
				t.Fatalf("errors.Is no longer reaches the original error: %v", got)
			}
		})
	}
}
