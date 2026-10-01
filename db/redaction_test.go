package db

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSantizeDbConn_RedactsCredentialForms(t *testing.T) {
	cases := []struct{ in, want string }{
		{"postgres://alice:hunter2@db:5432/app?password=hunter2&user=alice&sslmode=require#hunter2", "postgres://db:5432/app?sslmode=require"},
		{"postgresql://alice:p%40ss@db/app?sslpassword=secret&connect_timeout=5", "postgresql://db/app?connect_timeout=5"},
		{`host=db user='alice smith' password='hunter 2' dbname=app`, "host=db dbname=app"},
		{`host=db password='pa\'ss word' dbname=app`, "host=db dbname=app"},
		{`host=db password=hello\ world dbname=app`, "host=db dbname=app"},
		{`host=db PASSWORD='secret' options='secret' dbname=app`, "host=db dbname=app"},
		{`host=db password='unfinished secret`, "[invalid database connection string]"},
		{`postgres://alice:%invalid@db/app`, "[invalid database connection string]"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := SantizeDbConn(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWithDecimalRegister_PreservesAfterConnectError(t *testing.T) {
	want := errors.New("hook failed")
	called := false
	cfg := &pgxpool.Config{AfterConnect: func(context.Context, *pgx.Conn) error { called = true; return want }}
	WithDecimalRegister()(cfg)
	if err := cfg.AfterConnect(context.Background(), nil); !errors.Is(err, want) || !called {
		t.Fatalf("hook error=%v called=%v", err, called)
	}
}

func FuzzSantizeDbConn_RejectsMalformedCredentialTail(f *testing.F) {
	f.Add("hello world")
	f.Add("escaped\\' quote")
	f.Fuzz(func(t *testing.T, secret string) {
		// Malformed quoted credentials must never be echoed as a parser error.
		secret = strings.ReplaceAll(secret, "'", "")
		got := SantizeDbConn("host=db password='" + secret)
		if got != "[invalid database connection string]" {
			t.Fatalf("malformed DSN returned %q", got)
		}
	})
}
