package base

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/phuslu/log"
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

func TestWithLevelSlog(t *testing.T) {
	testCases := []struct {
		name     string
		input    slog.Level
		expected log.Level
	}{
		{"below-debug", slog.Level(-8), log.TraceLevel},
		{"debug", slog.LevelDebug, log.DebugLevel},
		{"debug-to-info", slog.Level(-2), log.DebugLevel},
		{"info", slog.LevelInfo, log.InfoLevel},
		{"info-to-warn", slog.Level(2), log.InfoLevel},
		{"warn", slog.LevelWarn, log.WarnLevel},
		{"warn-to-error", slog.Level(6), log.WarnLevel},
		{"error", slog.LevelError, log.ErrorLevel},
		{"above-error", slog.Level(12), log.ErrorLevel},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &appLoggerConfig{}
			WithLevel(tc.input)(cfg)
			assert.Equal(t, tc.expected, cfg.level)
		})
	}
}

func TestWithLevelPhuslu(t *testing.T) {
	testCases := []struct {
		name  string
		level log.Level
	}{
		{"trace", log.TraceLevel},
		{"debug", log.DebugLevel},
		{"info", log.InfoLevel},
		{"warn", log.WarnLevel},
		{"error", log.ErrorLevel},
		{"fatal", log.FatalLevel},
		{"panic", log.PanicLevel},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &appLoggerConfig{}
			WithLevel(tc.level)(cfg)
			assert.Equal(t, tc.level, cfg.level)
		})
	}
}

func TestAppLogger(t *testing.T) {
	testCases := []struct {
		name          string
		opts          []AppLoggerOption
		expectedLevel log.Level
		ctxContains   []string
		isMultiWriter bool
	}{
		{
			name:          "Defaults",
			opts:          nil,
			expectedLevel: log.InfoLevel,
			ctxContains:   []string{`"app":"myapp"`},
		},
		{
			name:        "WithSite",
			opts:        []AppLoggerOption{WithSite("tokyo")},
			ctxContains: []string{`"site":"tokyo"`, `"app":"myapp"`},
		},
		{
			name:        "WithModule",
			opts:        []AppLoggerOption{WithModule("api")},
			ctxContains: []string{`"module":"api"`, `"app":"myapp"`},
		},
		{
			name:          "WithLevelSlog",
			opts:          []AppLoggerOption{WithLevel(slog.LevelDebug)},
			expectedLevel: log.DebugLevel,
		},
		{
			name:          "WithLevelPhuslu",
			opts:          []AppLoggerOption{WithLevel(log.WarnLevel)},
			expectedLevel: log.WarnLevel,
		},
		{
			name:          "NilNatsUsesStdoutOnlyWriter",
			opts:          nil,
			isMultiWriter: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := AppLogger("myapp", nil, tc.opts...)
			if tc.expectedLevel != 0 {
				assert.Equal(t, tc.expectedLevel, logger.Level)
			}
			for _, s := range tc.ctxContains {
				assert.Contains(t, string(logger.Context), s)
			}
			_, isMulti := logger.Writer.(*log.MultiEntryWriter)
			assert.Equal(t, tc.isMultiWriter, isMulti)
		})
	}
}

func TestLoggerWithContext(t *testing.T) {
	base := AppLogger("myapp", nil, WithSite("tokyo"))

	testCases := []struct {
		name           string
		opts           []AppLoggerOption
		ctxContains    []string
		ctxNotContains []string
		checkBase      bool // verify opts do not mutate base
	}{
		{
			name:        "InheritsParentContext",
			opts:        []AppLoggerOption{WithModule("api")},
			ctxContains: []string{`"site":"tokyo"`, `"app":"myapp"`, `"module":"api"`},
		},
		{
			name:           "DoesNotMutateParent",
			opts:           []AppLoggerOption{WithModule("api")},
			ctxNotContains: []string{`"module":"api"`},
			checkBase:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			child := LoggerWithContext(&base, tc.opts...)
			assert.Equal(t, base.Level, child.Level)
			assert.Equal(t, base.Writer, child.Writer)

			target := child.Context
			if tc.checkBase {
				target = base.Context
			}
			for _, s := range tc.ctxContains {
				assert.Contains(t, string(target), s)
			}
			for _, s := range tc.ctxNotContains {
				assert.NotContains(t, string(target), s)
			}
		})
	}
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
