package api

import (
	"errors"
	"log"
	"net/url"
	"os"
	"strings"
)

// restyLogger replaces Resty's default logger, writing in the same format to
// stderr. Resty logs transport errors (every retry attempt and the final
// failure) before R sees them, and those errors embed the full request URL,
// so each URL is passed through redact before it is written.
type restyLogger struct {
	out    *log.Logger
	redact func(rawURL string) string
}

func newRestyLogger(redact func(rawURL string) string) restyLogger {
	return restyLogger{out: log.New(os.Stderr, "", log.Ldate|log.Lmicroseconds), redact: redact}
}

func (l restyLogger) Errorf(format string, v ...any) { l.output("ERROR RESTY "+format, v) }
func (l restyLogger) Warnf(format string, v ...any)  { l.output("WARN RESTY "+format, v) }
func (l restyLogger) Debugf(format string, v ...any) { l.output("DEBUG RESTY "+format, v) }

func (l restyLogger) output(format string, v []any) {
	if len(v) == 0 {
		l.out.Print(format)
		return
	}
	safe := make([]any, len(v))
	for i, arg := range v {
		safe[i] = l.redactArg(arg)
	}
	l.out.Printf(format, safe...)
}

// redactArg returns the message of a *url.Error argument with its URL
// replaced by the redacted form, at any depth of wrapping. Other arguments
// pass through unchanged.
func (l restyLogger) redactArg(arg any) any {
	err, ok := arg.(error)
	if !ok {
		return arg
	}
	ue, ok := errors.AsType[*url.Error](err)
	if !ok {
		return arg
	}
	return strings.ReplaceAll(err.Error(), ue.URL, l.redact(ue.URL))
}
