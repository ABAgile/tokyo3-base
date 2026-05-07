package db

import (
	"context"
	"fmt"
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
	connStrSanitizer      = regexp.MustCompile(`\b(user|password)=[^\s]+`)
	multiWhitespaceRegexp = regexp.MustCompile(`\s+`)
	pgPlaceholderRegexp   = regexp.MustCompile(`\$(\d+)`)
	byteSliceType         = reflect.TypeFor[[]byte]()
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
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			pgxDecimal.Register(conn.TypeMap())
			return nil
		}
	}
}

func SantizeDbConn(connStr string) string {
	cleaned := connStrSanitizer.ReplaceAllString(connStr, "")
	cleaned = multiWhitespaceRegexp.ReplaceAllString(cleaned, " ")
	return strings.TrimSpace(cleaned)
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
