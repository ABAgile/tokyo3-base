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

// AppLogger constructs a structured JSON logger for the named application.
//
// With no [WriterOption]s, output goes to stdout. Compose writers explicitly:
//
//	AppLogger("svc", WithStdout())                    // stdout only
//	AppLogger("svc", WithAsyncNats(nc))               // async NATS only
//	AppLogger("svc", WithStdout(), WithAsyncNats(nc)) // both
//
// The returned [*slog.LevelVar] controls the effective log level at runtime
// (default: Info). Adjust it with lv.Set(slog.LevelDebug) without restarting.
func AppLogger(app string, writerOpts ...WriterOption) (*slog.Logger, *slog.LevelVar) {
	var writers []log.Writer
	for _, opt := range writerOpts {
		opt(app, &writers)
	}

	var writer log.Writer
	switch len(writers) {
	case 0:
		writer = &log.IOWriter{Writer: os.Stdout}
	case 1:
		writer = writers[0]
	default:
		mw := log.MultiEntryWriter(writers)
		writer = &mw
	}

	phuslu := &log.Logger{Level: log.TraceLevel, Writer: writer}
	lv := new(slog.LevelVar)
	return slog.New(&levelHandler{level: lv, inner: phuslu.Slog().Handler()}).With("app", app), lv
}

type levelHandler struct {
	level *slog.LevelVar
	inner slog.Handler
}

func (h *levelHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *levelHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

func (h *levelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &levelHandler{h.level, h.inner.WithAttrs(attrs)}
}

func (h *levelHandler) WithGroup(name string) slog.Handler {
	return &levelHandler{h.level, h.inner.WithGroup(name)}
}

// WriterOption configures a log destination for [AppLogger].
// Use [WithStdout] and [WithAsyncNats] to compose the desired combination.
type WriterOption func(app string, ws *[]log.Writer)

// WithStdout adds a synchronous stdout writer.
func WithStdout() WriterOption {
	return func(_ string, ws *[]log.Writer) {
		*ws = append(*ws, &log.IOWriter{Writer: os.Stdout})
	}
}

// WithAsyncNats adds an async NATS writer that publishes to "app_log.<app>".
// Entries are discarded when the 200-entry channel is full.
func WithAsyncNats(nc *nats.Conn) WriterOption {
	return func(app string, ws *[]log.Writer) {
		*ws = append(*ws, &log.AsyncWriter{
			ChannelSize:   200,
			DiscardOnFull: true,
			Writer:        &log.IOWriter{Writer: &NatsWriter{Nc: nc, Subject: "app_log." + app}},
		})
	}
}

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
