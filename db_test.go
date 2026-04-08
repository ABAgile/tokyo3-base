package base

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
)

func TestNewPgxPool_InvalidConnStr(t *testing.T) {
	_, err := NewPgxPool("not a valid connstr %%%")
	assert.Error(t, err)
}

func TestNewPgxPool_WithOptions(t *testing.T) {
	// ParseConfig("") succeeds with defaults; pgxpool dials lazily so
	// NewWithConfig succeeds and options are applied without a real DB.
	pool, err := NewPgxPool("", WithDecimalRegister())
	if pool != nil {
		pool.Close()
	}
	assert.NoError(t, err)
}

func TestWithDecimalRegister(t *testing.T) {
	cfg := &pgxpool.Config{}
	opt := WithDecimalRegister()
	opt(cfg)
	assert.NotNil(t, cfg.AfterConnect)
}

func TestSantizeDbConn(t *testing.T) {
	testCases := []struct {
		name     string
		connStr  string
		expected string
	}{
		{
			"should remove user and password",
			"host=localhost port=5432 user=testuser password=testpass dbname=testdb",
			"host=localhost port=5432 dbname=testdb",
		},
		{
			"should handle no sensitive info",
			"host=localhost port=5432 dbname=testdb",
			"host=localhost port=5432 dbname=testdb",
		},
		{
			"should handle only user",
			"host=localhost port=5432 user=testuser dbname=testdb",
			"host=localhost port=5432 dbname=testdb",
		},
		{
			"should handle only password",
			"host=localhost port=5432 password=testpass dbname=testdb",
			"host=localhost port=5432 dbname=testdb",
		},
		{
			"should handle empty string",
			"",
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, SantizeDbConn(tc.connStr))
		})
	}
}

func TestConvertPgPlaceholders(t *testing.T) {
	testCases := []struct {
		name         string
		sql          string
		args         []any
		expectedSQL  string
		expectedArgs []any
		expectedErr  string
	}{
		{
			name:         "should convert placeholders in order",
			sql:          "SELECT * FROM users WHERE id = $1 AND name = $2",
			args:         []any{123, "test"},
			expectedSQL:  "SELECT * FROM users WHERE id = ? AND name = ?",
			expectedArgs: []any{123, "test"},
		},
		{
			name:         "should convert placeholders out of order",
			sql:          "INSERT INTO products (name, price) VALUES ($2, $1)",
			args:         []any{99.99, "gadget"},
			expectedSQL:  "INSERT INTO products (name, price) VALUES (?, ?)",
			expectedArgs: []any{"gadget", 99.99},
		},
		{
			name:         "should return original sql if no placeholders",
			sql:          "SELECT 1",
			args:         []any{},
			expectedSQL:  "SELECT 1",
			expectedArgs: []any{},
		},
		{
			name:        "should return error for invalid placeholder index",
			sql:         "SELECT * FROM users WHERE id = $3",
			args:        []any{1, 2},
			expectedErr: "invalid placeholder $3",
		},
		{
			name:        "should return error for placeholder index 0",
			sql:         "SELECT * FROM users WHERE id = $0",
			args:        []any{1},
			expectedErr: "invalid placeholder $0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			newSQL, newArgs, err := ConvertPgPlaceholders(tc.sql, tc.args...)
			if tc.expectedErr != "" {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedErr, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedSQL, newSQL)
				assert.Equal(t, tc.expectedArgs, newArgs)
			}
		})
	}
}

func TestCopyDeref(t *testing.T) {
	type Source struct {
		ID      int
		Name    *string
		Data    []byte
		Missing string
	}

	type Dest struct {
		ID    int
		Name  string
		Data  string
		Extra int
	}

	srcName := "source_name"
	ptrSrcName := "ptr_source"

	testCases := []struct {
		name        string
		src         any
		dst         *Dest
		expectedDst Dest
	}{
		{
			name:        "should copy fields correctly",
			src:         Source{ID: 123, Name: &srcName, Data: []byte("source_data")},
			dst:         &Dest{},
			expectedDst: Dest{ID: 123, Name: "source_name", Data: "source_data"},
		},
		{
			name:        "should handle nil pointer in source",
			src:         Source{ID: 456, Name: nil},
			dst:         &Dest{Name: "original_name"},
			expectedDst: Dest{ID: 456, Name: ""}, // Zero value for string is ""
		},
		{
			name:        "should handle pointer to struct as source",
			src:         &Source{ID: 789, Name: &ptrSrcName},
			dst:         &Dest{},
			expectedDst: Dest{ID: 789, Name: "ptr_source"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CopyDeref(tc.src, tc.dst)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedDst, *result)
		})
	}
}

func TestCopyDeref_ErrorCases(t *testing.T) {
	type Source struct {
		ID int
	}
	type Dest struct {
		ID int
	}

	t.Run("should return error for non-struct source", func(t *testing.T) {
		_, err := CopyDeref(123, &Dest{})
		assert.Error(t, err)
		assert.Equal(t, "expected struct types", err.Error())
	})

	t.Run("should return error for non-struct destination", func(t *testing.T) {
		_, err := CopyDeref(Source{}, new(int))
		assert.Error(t, err)
		assert.Equal(t, "expected struct types", err.Error())
	})
}
