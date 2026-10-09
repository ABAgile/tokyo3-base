package db

import (
	"context"
	"testing"
)

// An unparseable connection string must fail before any pool is built.
func TestNewPgxPoolContext_RejectsUnparseableConnStr(t *testing.T) {
	pool, err := NewPgxPoolContext(context.Background(), "not a valid connstr %%%")
	if err == nil {
		pool.Close()
		t.Fatal("NewPgxPoolContext accepted an unparseable connection string")
	}
	if pool != nil {
		t.Errorf("pool = %v, want nil on error", pool)
	}
}

// A keyword-form string that cannot be tokenised is reported as a placeholder,
// not echoed back, so a malformed credential can never leak into logs.
func TestSanitizeDBConn_UnparseableKeywordFormIsPlaceholder(t *testing.T) {
	got := SanitizeDBConn("host=db password=hunter2 %%%")
	if got != "[invalid database connection string]" {
		t.Errorf("SanitizeDBConn = %q, want the invalid placeholder", got)
	}
}

// An unterminated literal, comment, or dollar-quote extends to the end of the
// SQL, so nothing after its opening is treated as a placeholder. Placeholders
// before it are still converted.
func TestConvertPgPlaceholders_UnterminatedLiteralsSwallowRest(t *testing.T) {
	cases := []struct {
		name    string
		sql     string
		wantSQL string
	}{
		{"unterminated single quote", "SELECT '$1", "SELECT '$1"},
		{"unterminated double quote", `SELECT "$1`, `SELECT "$1`},
		{"unterminated dollar quote", "SELECT $$ $1", "SELECT $$ $1"},
		{"unterminated block comment", "SELECT /* $1", "SELECT /* $1"},
		{"placeholder before unterminated line comment", "SELECT $1 -- $2", "SELECT ? -- $2"},
		{"placeholder before unterminated block comment", "SELECT $1 /* $2", "SELECT ? /* $2"},
		{"placeholder before unterminated dollar quote", "SELECT $1::int, $tag$ open $1", "SELECT ?::int, $tag$ open $1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotArgs, err := ConvertPgPlaceholders(tc.sql, "a")
			if err != nil {
				t.Fatalf("ConvertPgPlaceholders(%q): %v", tc.sql, err)
			}
			if got != tc.wantSQL {
				t.Errorf("sql = %q, want %q", got, tc.wantSQL)
			}
			// Every case has one caller argument, and it must come back as the sole
			// argument whether or not anything was converted.
			if len(gotArgs) != 1 || gotArgs[0] != "a" {
				t.Errorf("args = %v, want [a]", gotArgs)
			}
		})
	}
}
