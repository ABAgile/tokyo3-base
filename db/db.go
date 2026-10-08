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
	connStrFieldRegexp = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*('(?:\\.|[^'\\])*'|(?:\\.|[^\s'\\])+|)`)
	byteSliceType      = reflect.TypeFor[[]byte]()
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

// ConvertPgPlaceholders rewrites PostgreSQL-style $n placeholders to "?" and
// returns the args reordered to match. Text that merely looks like a
// placeholder is left alone: single-quoted strings, quoted identifiers,
// -- and /* */ comments, and dollar-quoted bodies ($$…$$, $tag$…$tag$).
func ConvertPgPlaceholders(sql string, args ...any) (string, []any, error) {
	var (
		b           strings.Builder
		orderedArgs []any
		found       bool
	)
	b.Grow(len(sql))

	for i := 0; i < len(sql); {
		end := skipLiteral(sql, i)
		if end > i {
			b.WriteString(sql[i:end])
			i = end
			continue
		}
		if sql[i] == '$' {
			j := i + 1
			for j < len(sql) && sql[j] >= '0' && sql[j] <= '9' {
				j++
			}
			if j > i+1 {
				numStr := sql[i+1 : j]
				n, err := strconv.Atoi(numStr)
				if err != nil || n < 1 || n > len(args) {
					return "", nil, fmt.Errorf("invalid placeholder $%s", numStr)
				}
				found = true
				b.WriteByte('?')
				orderedArgs = append(orderedArgs, args[n-1])
				i = j
				continue
			}
		}
		b.WriteByte(sql[i])
		i++
	}

	if !found {
		return sql, args, nil
	}
	return b.String(), orderedArgs, nil
}

// skipLiteral returns the index just past the quoted string, quoted
// identifier, comment or dollar-quoted body starting at sql[i], or i if none
// starts there. An unterminated literal extends to the end of sql.
func skipLiteral(sql string, i int) int {
	switch c := sql[i]; {
	case c == '\'' || c == '"':
		for j := i + 1; j < len(sql); j++ {
			if sql[j] == c {
				if j+1 < len(sql) && sql[j+1] == c { // doubled quote is an escape
					j++
					continue
				}
				return j + 1
			}
		}
		return len(sql)
	case c == '-' && strings.HasPrefix(sql[i:], "--"):
		if nl := strings.IndexByte(sql[i:], '\n'); nl >= 0 {
			return i + nl + 1
		}
		return len(sql)
	case c == '/' && strings.HasPrefix(sql[i:], "/*"):
		depth := 0 // PostgreSQL block comments nest
		for j := i; j < len(sql); j++ {
			switch {
			case strings.HasPrefix(sql[j:], "/*"):
				depth++
				j++
			case strings.HasPrefix(sql[j:], "*/"):
				depth--
				j++
				if depth == 0 {
					return j + 1
				}
			}
		}
		return len(sql)
	case c == '$':
		// $tag$ opens a dollar-quote; a tag may not start with a digit, which
		// keeps $1 a placeholder.
		j := i + 1
		for j < len(sql) && (sql[j] == '_' || sql[j] >= 'a' && sql[j] <= 'z' || sql[j] >= 'A' && sql[j] <= 'Z' || sql[j] >= 0x80 || j > i+1 && sql[j] >= '0' && sql[j] <= '9') {
			j++
		}
		if j >= len(sql) || sql[j] != '$' {
			return i
		}
		delim := sql[i : j+1]
		if k := strings.Index(sql[j+1:], delim); k >= 0 {
			return j + 1 + k + len(delim)
		}
		return len(sql)
	}
	return i
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
