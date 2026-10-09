package db

import "testing"

// A URL-form DSN is logged only as routing fields. If its query cannot be
// parsed, it must be replaced by the placeholder rather than echoed, since a
// credential could sit in the malformed part.
func TestSanitizeDBConn_URLWithBadQueryIsPlaceholder(t *testing.T) {
	const placeholder = "[invalid database connection string]"
	for _, in := range []string{
		"postgres://alice:hunter2@db/app?sslmode=%zz",
		"mysql://alice:hunter2@db/app", // not a PostgreSQL scheme
	} {
		if got := SanitizeDBConn(in); got != placeholder {
			t.Errorf("SanitizeDBConn(%q) = %q, want the placeholder", in, got)
		}
	}
}
