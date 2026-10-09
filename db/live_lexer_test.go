package db

import (
	"fmt"
	"testing"

	"github.com/abagile/tokyo3-base/internal/livetest"
	"github.com/stretchr/testify/require"
)

// TestLiveConvertPgPlaceholdersAgreesWithServerLexer checks the placeholder
// lexer against PostgreSQL's own parser. For each statement the server reports
// how many parameters it expects, and the converter must find exactly that
// many placeholders. The statements put $n inside literals, comments, and
// identifiers, where the converter must skip them. A wrong guess either fails
// with an invalid-placeholder error (the converter reads $n as a parameter the
// caller did not supply) or returns a different count.
//
// Prepare sends the statement to the server but runs nothing, so the test
// only reads from the database. It skips unless BASE_TEST_DATABASE_URL is set.
func TestLiveConvertPgPlaceholdersAgreesWithServerLexer(t *testing.T) {
	dsn := livetest.PostgresDSN(t)
	ctx := liveCtx(t)
	pool, err := NewPgxPoolContext(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	t.Cleanup(conn.Release)

	cases := []struct {
		name string
		sql  string
		want int // parameters the server expects
	}{
		{"placeholder in single-quoted literal", `SELECT $1::int, '$2'::text`, 1},
		{"placeholder in block comment", `SELECT $1::int /* $3 */, $2::text`, 2},
		{"placeholder in line comment", "SELECT $1::int -- $9\n, $2::text", 2},
		{"placeholder in dollar quote", `SELECT $$ $2 $$, $1::int`, 1},
		{"placeholder in tagged dollar quote", `SELECT $tag$ $1 $tag$, $1::int`, 1},
		{"placeholder in quoted identifier", `SELECT 1 AS "col$2", $1::int`, 1},
		{"escaped quote in E-string", `SELECT E'\'$2', $1::int`, 1},
		{"backslash in standard string", `SELECT '\', $1::int`, 1},
		{"doubled quote in literal", `SELECT 'it''s $2', $1::int`, 1},
		{"nested block comment", `SELECT /* outer /* $3 */ still $4 */ $1::int`, 1},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			desc, err := conn.Conn().Prepare(ctx, fmt.Sprintf("lexer_%d", i), tc.sql)
			require.NoError(t, err, "server rejected the statement")
			require.Len(t, desc.ParamOIDs, tc.want, "server parameter count")

			_, args, err := ConvertPgPlaceholders(tc.sql, make([]any, tc.want)...)
			require.NoError(t, err, "converter disagreed with the server about the placeholders")
			require.Len(t, args, tc.want, "converter placeholder count")
		})
	}
}
