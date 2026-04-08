package base

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/phuslu/log"
)

type NatsWriter struct {
	Nc      *nats.Conn
	Subject string
}

func (nw *NatsWriter) Write(p []byte) (n int, err error) {
	err = nw.Nc.Publish(nw.Subject, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

type AppLoggerOption func(*appLoggerConfig)

type appLoggerConfig struct {
	level log.Level
	ctx   log.Context
}

func WithLevel[L slog.Level | log.Level](level L) AppLoggerOption {
	return func(cfg *appLoggerConfig) { cfg.level = toPhusluLevel(any(level)) }
}

func toPhusluLevel(level any) log.Level {
	switch l := level.(type) {
	case slog.Level:
		switch {
		case l < slog.LevelDebug:
			return log.TraceLevel
		case l < slog.LevelInfo:
			return log.DebugLevel
		case l < slog.LevelWarn:
			return log.InfoLevel
		case l < slog.LevelError:
			return log.WarnLevel
		default:
			return log.ErrorLevel
		}
	default:
		return l.(log.Level)
	}
}

func WithSite(site string) AppLoggerOption {
	return func(cfg *appLoggerConfig) {
		cfg.ctx = log.NewContext(cfg.ctx).Str("site", site).Value()
	}
}

func WithModule(module string) AppLoggerOption {
	return func(cfg *appLoggerConfig) {
		cfg.ctx = log.NewContext(cfg.ctx).Str("module", module).Value()
	}
}

func AppLogger(app string, nc *nats.Conn, opts ...AppLoggerOption) log.Logger {
	cfg := &appLoggerConfig{level: log.InfoLevel}
	for _, opt := range opts {
		opt(cfg)
	}

	ctx := log.NewContext(cfg.ctx).Str("app", app).Value()

	var writer log.Writer = &log.IOWriter{Writer: os.Stdout}
	if nc != nil {
		writer = &log.MultiEntryWriter{
			&log.IOWriter{Writer: os.Stdout},
			&log.AsyncWriter{
				ChannelSize:   200,
				DiscardOnFull: true,
				Writer: &log.IOWriter{Writer: &NatsWriter{
					Nc:      nc,
					Subject: "app_log." + app,
				}},
			},
		}
	}

	return log.Logger{Level: cfg.level, Context: ctx, Writer: writer}
}

func LoggerWithContext(l *log.Logger, opts ...AppLoggerOption) *log.Logger {
	cfg := &appLoggerConfig{ctx: l.Context}
	for _, opt := range opts {
		opt(cfg)
	}
	return &log.Logger{Level: l.Level, Writer: l.Writer, Context: cfg.ctx}
}

// AttrsHandler is a slog.Handler that appends attributes to the log message
// in human-readable form ("|>> key: [val], ..."), while also forwarding all
// structured fields to the inner handler unchanged.
// Attrs with a "_" key prefix are excluded from the message annotation.
// Group prefixes (from WithGroup) apply to structured fields only, not to the
// message annotation.
type AttrsHandler struct {
	inner     slog.Handler
	withAttrs []slog.Attr
}

func NewAttrsLogger(inner slog.Handler) *slog.Logger {
	return slog.New(&AttrsHandler{inner: inner})
}

func (h *AttrsHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *AttrsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AttrsHandler{
		inner:     h.inner.WithAttrs(attrs),
		withAttrs: append(append([]slog.Attr(nil), h.withAttrs...), attrs...),
	}
}

func (h *AttrsHandler) WithGroup(name string) slog.Handler {
	return &AttrsHandler{
		inner:     h.inner.WithGroup(name),
		withAttrs: append([]slog.Attr(nil), h.withAttrs...),
	}
}

func (h *AttrsHandler) Handle(ctx context.Context, r slog.Record) error {
	var combined []slog.Attr
	for _, a := range h.withAttrs {
		if !strings.HasPrefix(a.Key, "_") {
			combined = append(combined, a)
		}
	}
	r.Attrs(func(a slog.Attr) bool {
		if !strings.HasPrefix(a.Key, "_") {
			combined = append(combined, a)
		}
		return true
	})

	if len(combined) > 0 {
		var sb strings.Builder
		sb.WriteString(r.Message)
		sb.WriteString(" |>> ")
		for i, a := range combined {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(a.Key)
			sb.WriteString(": [")
			fmt.Fprint(&sb, a.Value.Any())
			sb.WriteString("]")
		}
		nr := slog.NewRecord(r.Time, r.Level, sb.String(), r.PC)
		r.Attrs(func(a slog.Attr) bool {
			nr.AddAttrs(a)
			return true
		})
		r = nr
	}

	return h.inner.Handle(ctx, r)
}

// StackFrame returns a formatted stack trace, starting skip frames above the
// caller (skip=0 starts at the direct caller of StackFrame). Only frames whose
// function name has a prefix in targetPkgs are included; pass no targetPkgs to
// include all frames.
func StackFrame(skip int, targetPkgs ...string) string {
	buf := make([]uintptr, 64)
	n := runtime.Callers(skip+2, buf)
	frames := runtime.CallersFrames(buf[:n])
	var res strings.Builder
	for {
		frame, more := frames.Next()
		if len(targetPkgs) == 0 || slices.ContainsFunc(targetPkgs, func(p string) bool {
			return strings.HasPrefix(frame.Function, p)
		}) {
			fmt.Fprintf(&res, "%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line)
		}
		if !more {
			break
		}
	}
	return res.String()
}
