package db

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/internal/livetest"
	"github.com/govalues/decimal"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// The tests in this file run against a live PostgreSQL server. They skip
// unless BASE_TEST_DATABASE_URL is set (see package livetest). They issue only
// read-only queries, so they never change the database they point at.

func liveCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestLiveNewPgxPoolContextPings(t *testing.T) {
	dsn := livetest.PostgresDSN(t)
	ctx := liveCtx(t)

	pool, err := NewPgxPoolContext(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	var one int
	require.NoError(t, pool.QueryRow(ctx, "SELECT 1").Scan(&one))
	require.Equal(t, 1, one)
}

// liveURL returns BASE_TEST_DATABASE_URL parsed as a postgres:// URL.
func liveURL(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse(livetest.PostgresDSN(t))
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, u.Scheme, "BASE_TEST_DATABASE_URL must be a postgres:// URL")
	return u
}

// TestLiveNewPgxPoolContextRedactsServerError: a real server rejection (a
// database that does not exist) is reported without the password. The DSN's
// own password is used so the login succeeds and the server reaches the
// missing-database check; a trust-auth server accepts any placeholder.
func TestLiveNewPgxPoolContextRedactsServerError(t *testing.T) {
	u := liveURL(t)
	password, ok := u.User.Password()
	if !ok || password == "" {
		password = "s3cret-live-pw"
	}
	u.User = url.UserPassword(u.User.Username(), password)
	u.Path = "/" + livetest.UniqueName(t, "basetest_missing_")

	pool, err := NewPgxPoolContext(liveCtx(t), u.String())
	require.Nil(t, pool)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ping database")
	require.Contains(t, err.Error(), "does not exist", "failure should come from the server")
	require.NotContains(t, err.Error(), password)
}

// TestLiveNewPgxPoolContextRejectsWrongPassword: a login the server does not
// accept fails startup with invalid_password (SQLSTATE 28P01), and the attempted
// password is not echoed. A trust-auth server accepts any password, so there is
// nothing to reject and the test skips.
func TestLiveNewPgxPoolContextRejectsWrongPassword(t *testing.T) {
	u := liveURL(t)
	const wrong = "wrong-live-pw-9d2e"
	u.User = url.UserPassword(u.User.Username(), wrong)

	pool, err := NewPgxPoolContext(liveCtx(t), u.String())
	if err == nil {
		pool.Close()
		t.Skip("server accepts any password (trust auth); nothing to reject")
	}
	require.Nil(t, pool)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "28P01", pgErr.Code)
	require.NotContains(t, err.Error(), wrong)
}

// TestLiveWithDecimalRegisterInstallsCodec: the AfterConnect hook runs on a
// real connection and installs the govalues decimal codec. Without the option,
// the connection's type map has no entry for decimal.Decimal.
func TestLiveWithDecimalRegisterInstallsCodec(t *testing.T) {
	dsn := livetest.PostgresDSN(t)
	ctx := liveCtx(t)
	cases := []struct {
		name      string
		opts      []DatabaseConfigOption
		wantCodec bool
	}{
		{"without option", nil, false},
		{"with WithDecimalRegister", []DatabaseConfigOption{WithDecimalRegister()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := NewPgxPoolContext(ctx, dsn, tc.opts...)
			require.NoError(t, err)
			t.Cleanup(pool.Close)

			conn, err := pool.Acquire(ctx)
			require.NoError(t, err)
			defer conn.Release()
			dt, _ := conn.Conn().TypeMap().TypeForValue(decimal.Decimal{})
			if !tc.wantCodec {
				require.Nil(t, dt)
				return
			}
			require.NotNil(t, dt)
			require.Equal(t, "numeric", dt.Name)
		})
	}
}

// TestLiveWithDecimalRegisterRoundTripsNumeric: a govalues decimal round-trips
// through a pooled connection with the option. The value has 19 significant
// digits, more than float64 can hold.
func TestLiveWithDecimalRegisterRoundTripsNumeric(t *testing.T) {
	dsn := livetest.PostgresDSN(t)
	ctx := liveCtx(t)

	pool, err := NewPgxPoolContext(ctx, dsn, WithDecimalRegister())
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	in := decimal.MustParse("1234567890123.456789")
	var out decimal.Decimal
	require.NoError(t, pool.QueryRow(ctx, "SELECT $1::numeric", in).Scan(&out))
	require.Equal(t, in.String(), out.String())
}
