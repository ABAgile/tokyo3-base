package applog

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttrsHandler(t *testing.T) {
	var buf bytes.Buffer

	testCases := []struct {
		name     string
		setup    func(logger *slog.Logger) *slog.Logger
		logAttrs []slog.Attr
		expected string
	}{
		{
			name:     "LogAttrs",
			setup:    func(logger *slog.Logger) *slog.Logger { return logger },
			logAttrs: []slog.Attr{slog.String("key", "value")},
			expected: `level=INFO msg="test message |>> key: [value]" key=value`,
		},
		{
			name: "With",
			setup: func(logger *slog.Logger) *slog.Logger {
				return logger.With(slog.String("with_key", "with_value"))
			},
			logAttrs: []slog.Attr{slog.String("key", "value")},
			expected: `level=INFO msg="test message |>> with_key: [with_value], key: [value]" with_key=with_value key=value`,
		},
		{
			name: "WithGroup",
			setup: func(logger *slog.Logger) *slog.Logger {
				return logger.WithGroup("group1")
			},
			logAttrs: []slog.Attr{slog.String("key", "value")},
			expected: `level=INFO msg="test message |>> key: [value]" group1.key=value`,
		},
		{
			name:     "UnderscoreAttrsExcludedFromMessage",
			setup:    func(logger *slog.Logger) *slog.Logger { return logger },
			logAttrs: []slog.Attr{slog.String("key", "value"), slog.String("_hidden", "secret")},
			expected: `level=INFO msg="test message |>> key: [value]" key=value _hidden=secret`,
		},
		{
			name: "UnderscoreWithAttrsExcludedFromMessage",
			setup: func(logger *slog.Logger) *slog.Logger {
				return logger.With(slog.String("_trace", "abc"), slog.String("env", "prod"))
			},
			logAttrs: []slog.Attr{slog.String("key", "value")},
			expected: `level=INFO msg="test message |>> env: [prod], key: [value]" _trace=abc env=prod key=value`,
		},
		{
			name:     "NoAttrs",
			setup:    func(logger *slog.Logger) *slog.Logger { return logger },
			logAttrs: []slog.Attr{},
			expected: `level=INFO msg="test message"`,
		},
		{
			name:     "OnlyUnderscoreAttrs",
			setup:    func(logger *slog.Logger) *slog.Logger { return logger },
			logAttrs: []slog.Attr{slog.String("_hidden", "secret")},
			expected: `level=INFO msg="test message" _hidden=secret`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			logger := NewAttrsLogger(slog.NewTextHandler(&buf, nil))
			logger = tc.setup(logger)
			logger.LogAttrs(context.Background(), slog.LevelInfo, "test message", tc.logAttrs...)
			assert.Contains(t, buf.String(), tc.expected)
		})
	}
}

func TestAppLogger(t *testing.T) {
	t.Run("DefaultLevelIsInfo", func(t *testing.T) {
		_, lv := AppLogger("myapp")
		assert.Equal(t, slog.LevelInfo, lv.Level())
	})

	t.Run("LevelVarGatesEnabled", func(t *testing.T) {
		logger, lv := AppLogger("myapp")
		lv.Set(slog.LevelWarn)
		assert.False(t, logger.Enabled(context.Background(), slog.LevelInfo))
		assert.True(t, logger.Enabled(context.Background(), slog.LevelWarn))
		assert.True(t, logger.Enabled(context.Background(), slog.LevelError))
	})

	t.Run("LevelVarIsAdjustable", func(t *testing.T) {
		logger, lv := AppLogger("myapp")
		assert.False(t, logger.Enabled(context.Background(), slog.LevelDebug))
		lv.Set(slog.LevelDebug)
		assert.True(t, logger.Enabled(context.Background(), slog.LevelDebug))
	})
}

func TestStackFrame(t *testing.T) {
	testCases := []struct {
		name        string
		skip        int
		targetPkgs  []string
		contains    string
		notContains string
		empty       bool
	}{
		{
			name:     "AllFrames",
			skip:     0,
			contains: "TestStackFrame",
		},
		{
			name:        "FilteredByPackage",
			skip:        0,
			targetPkgs:  []string{"github.com/abagile/tokyo3-base"},
			contains:    "TestStackFrame",
			notContains: "testing.tRunner",
		},
		{
			name:       "NoMatchingPackage",
			skip:       0,
			targetPkgs: []string{"nonexistent/package"},
			empty:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := StackFrame(tc.skip, tc.targetPkgs...)
			if tc.empty {
				assert.Empty(t, result)
				return
			}
			if tc.contains != "" {
				assert.Contains(t, result, tc.contains)
			}
			if tc.notContains != "" {
				assert.False(t, strings.Contains(result, tc.notContains))
			}
		})
	}

	t.Run("SkipReducesFrameCount", func(t *testing.T) {
		all := StackFrame(0)
		fewer := StackFrame(1)
		assert.Greater(t, strings.Count(all, "\n"), strings.Count(fewer, "\n"))
	})
}
