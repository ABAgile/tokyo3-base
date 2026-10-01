package db

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	pgxDecimal "github.com/ColeBurch/pgx-govalues-decimal"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DatabaseConfigOption func(*pgxpool.Config)

var (
	connStrFieldRegexp  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*('(?:\\.|[^'\\])*'|(?:\\.|[^\s'\\])+|)`)
	pgPlaceholderRegexp = regexp.MustCompile(`\$(\d+)`)
	byteSliceType       = reflect.TypeFor[[]byte]()
)

func NewPgxPool(connStr string, opts ...DatabaseConfigOption) (*pgxpool.Pool, error) {
	pgConf, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, err
	}
	for _, opt := range opts {
		opt(pgConf)
	}
	return pgxpool.NewWithConfig(context.Background(), pgConf)
}

func WithDecimalRegister() DatabaseConfigOption {
	return func(cfg *pgxpool.Config) {
		previous := cfg.AfterConnect
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			if previous != nil {
				if err := previous(ctx, conn); err != nil {
					return err
				}
			}
			pgxDecimal.Register(conn.TypeMap())
			return nil
		}
	}
}

// SantizeDbConn returns a logging-safe connection summary. Only connection
// routing fields are retained, never credentials or arbitrary parameters.
// The historical spelling is retained for source compatibility.
func SantizeDbConn(connStr string) string {
	if strings.Contains(connStr, "://") {
		u, err := url.Parse(connStr)
		if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
			return "[invalid database connection string]"
		}
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return "[invalid database connection string]"
		}
		u.User = nil
		u.Fragment = ""
		for key := range query {
			if !safeConnField(key) {
				delete(query, key)
			}
		}
		u.RawQuery = query.Encode()
		u.ForceQuery = false
		return u.String()
	}
	var fields []string
	for rest := strings.TrimSpace(connStr); rest != ""; {
		match := connStrFieldRegexp.FindStringSubmatchIndex(rest)
		if match == nil {
			return "[invalid database connection string]"
		}
		if safeConnField(rest[match[2]:match[3]]) {
			fields = append(fields, rest[:match[1]])
		}
		rest = strings.TrimSpace(rest[match[1]:])
	}
	return strings.Join(fields, " ")
}

func safeConnField(key string) bool {
	switch strings.ToLower(key) {
	case "host", "port", "dbname", "sslmode", "application_name", "connect_timeout":
		return true
	default:
		return false
	}
}

func ConvertPgPlaceholders(sql string, args ...any) (string, []any, error) {
	matches := pgPlaceholderRegexp.FindAllStringSubmatchIndex(sql, -1)

	if len(matches) == 0 {
		return sql, args, nil
	}

	var b strings.Builder
	b.Grow(len(sql))
	orderedArgs := make([]any, 0, len(matches))

	last := 0
	for _, m := range matches {
		start, end := m[0], m[1]
		numStart, numEnd := m[2], m[3]

		b.WriteString(sql[last:start])
		b.WriteString("?")
		last = end

		numStr := sql[numStart:numEnd]
		n, err := strconv.Atoi(numStr)
		if err != nil || n < 1 || n > len(args) {
			return "", nil, fmt.Errorf("invalid placeholder $%s", numStr)
		}

		orderedArgs = append(orderedArgs, args[n-1])
	}

	b.WriteString(sql[last:])

	return b.String(), orderedArgs, nil
}

func CopyDeref[T any, U any](src T, dst *U) (*U, error) {
	srcVal := reflect.ValueOf(src)
	dstVal := reflect.ValueOf(dst).Elem()

	if srcVal.Kind() == reflect.Pointer {
		srcVal = srcVal.Elem()
	}
	if srcVal.Kind() != reflect.Struct || dstVal.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct types")
	}

	dstType := dstVal.Type()

	for i := 0; i < dstType.NumField(); i++ {
		dstField := dstVal.Field(i)
		dstFieldType := dstType.Field(i)

		srcField := srcVal.FieldByName(dstFieldType.Name)
		if !srcField.IsValid() || !dstField.CanSet() {
			continue
		}

		switch {
		case srcField.Type() == byteSliceType && dstField.Kind() == reflect.String:
			dstField.SetString(string(srcField.Bytes()))
		case srcField.Kind() == reflect.Pointer && srcField.Type().Elem().AssignableTo(dstField.Type()):
			if srcField.IsNil() {
				dstField.Set(reflect.Zero(dstField.Type()))
			} else {
				dstField.Set(srcField.Elem())
			}
		case srcField.Type().AssignableTo(dstField.Type()):
			dstField.Set(srcField)
		}
	}

	return dst, nil
}
