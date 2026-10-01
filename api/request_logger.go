package api

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/go-resty/resty/v2"
)

const logAttrsKey contextKey = "logAttrs"

// WithLogAttr adds a single key-value pair into the context log attributes map.
// All entries are automatically appended to outgoing request and incoming response log messages.
func WithLogAttr(ctx context.Context, key, value string) context.Context {
	existing, _ := ctx.Value(logAttrsKey).(map[string]string)
	next := make(map[string]string, len(existing)+1)
	maps.Copy(next, existing)
	next[key] = value
	return context.WithValue(ctx, logAttrsKey, next)
}

// WithLogAttrs adds multiple key-value pairs into the context log attributes map.
func WithLogAttrs(ctx context.Context, attrs map[string]string) context.Context {
	existing, _ := ctx.Value(logAttrsKey).(map[string]string)
	next := make(map[string]string, len(existing)+len(attrs))
	maps.Copy(next, existing)
	maps.Copy(next, attrs)
	return context.WithValue(ctx, logAttrsKey, next)
}

func logAttrsSuffix(attrs map[string]string) string {
	if len(attrs) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(" |>>")
	for _, k := range slices.Sorted(maps.Keys(attrs)) {
		fmt.Fprintf(&sb, " %s: [%s]", k, attrs[k])
	}
	return sb.String()
}

func logAttrsToSlog(attrs map[string]string) []slog.Attr {
	if len(attrs) == 0 {
		return nil
	}
	keys := slices.Sorted(maps.Keys(attrs))
	result := make([]slog.Attr, len(keys))
	for i, k := range keys {
		result[i] = slog.String(k, attrs[k])
	}
	return result
}

const redactedLogValue = "***redacted***"

func isSensitiveLogField(name string) bool {
	key := strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(name))
	if key == "signature" || key == "sig" {
		return true
	}
	for _, part := range []string{"auth", "cookie", "key", "code", "token", "secret", "password", "passwd", "passphrase", "credential", "assertion", "session", "nonce", "state", "verifier", "csrf", "jwt"} {
		if strings.Contains(key, part) {
			return true
		}
	}
	return false
}

func sanitizeQuery(values url.Values) url.Values {
	safe := make(url.Values, len(values))
	for key, vals := range values {
		if isSensitiveLogField(key) {
			safe[key] = []string{redactedLogValue}
		} else {
			safe[key] = vals
		}
	}
	return safe
}

func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid URL]"
	}
	if u.User != nil {
		u.User = url.User(redactedLogValue)
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		u.RawQuery = ""
		u.ForceQuery = false
		return u.String()
	}
	u.RawQuery = sanitizeQuery(query).Encode()
	if u.RawQuery == "" {
		u.ForceQuery = false
	}
	return u.String()
}

func sanitizeRequestURL(raw string, pathParams map[string]string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return sanitizeURL(raw)
	}
	for key, value := range pathParams {
		if value != "" && isSensitiveLogField(key) {
			u.Path = strings.ReplaceAll(u.Path, value, redactedLogValue)
			u.RawPath = ""
		}
	}
	return sanitizeURL(u.String())
}

func sanitizeLogAttrs(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return attrs
	}
	safe := make(map[string]string, len(attrs))
	for key, value := range attrs {
		if isSensitiveLogField(key) {
			value = redactedLogValue
		}
		safe[key] = value
	}
	return safe
}

// SanitizeHeaders returns a copy of h with sensitive header values redacted.
func SanitizeHeaders(h map[string][]string) map[string][]string {
	safe := make(map[string][]string, len(h))
	for k, v := range h {
		if isSensitiveLogField(k) {
			safe[k] = []string{redactedLogValue}
		} else {
			safe[k] = v
		}
	}
	return safe
}

// WithRequestLogger adds structured request/response metadata logging. Bodies
// are omitted, and credential-like headers, URL fields, and context attributes
// are redacted by name.
func (co *ClientOption) WithRequestLogger(logger *slog.Logger) RestyClientOption {
	return func(c *resty.Client) {
		if logger == nil {
			logger = slog.Default()
		}
		c.OnBeforeRequest(func(_ *resty.Client, r *resty.Request) error {
			queryStr := sanitizeQuery(r.QueryParam).Encode()
			requestURL := sanitizeRequestURL(r.URL, r.PathParams)
			fullURL := requestURL
			if queryStr != "" {
				separator := "?"
				if strings.Contains(fullURL, "?") {
					separator = "&"
				}
				fullURL += separator + queryStr
			}
			pathParamStr := ""
			if len(r.PathParams) > 0 {
				pathParams := sanitizeLogAttrs(r.PathParams)
				pathParamStr = fmt.Sprintf("%v", pathParams)
				fullURL += " " + strings.TrimPrefix(pathParamStr, "map")
			}
			attrs, _ := r.Context().Value(logAttrsKey).(map[string]string)
			attrs = sanitizeLogAttrs(attrs)
			logAttrs := append([]slog.Attr{
				slog.String("method", r.Method),
				slog.String("url", requestURL),
				slog.String("queryParam", queryStr),
				slog.String("pathParam", pathParamStr),
				slog.Any("header", SanitizeHeaders(r.Header)),
			}, logAttrsToSlog(attrs)...)
			logger.LogAttrs(r.Context(), slog.LevelInfo,
				fmt.Sprintf("OUTGOING_REQUEST: %s %s%s", r.Method, fullURL, logAttrsSuffix(attrs)),
				logAttrs...,
			)
			return nil
		})

		c.OnAfterResponse(func(_ *resty.Client, r *resty.Response) error {
			attrs, _ := r.Request.Context().Value(logAttrsKey).(map[string]string)
			attrs = sanitizeLogAttrs(attrs)
			requestURL := sanitizeRequestURL(r.Request.URL, r.Request.PathParams)
			logAttrs := append([]slog.Attr{
				slog.String("method", r.Request.Method),
				slog.String("url", requestURL),
				slog.Int("status", r.StatusCode()),
				slog.Any("header", SanitizeHeaders(r.Header())),
				slog.String("elapsed", r.Time().String()),
				slog.Duration("elapsed_ms", r.Time()),
			}, logAttrsToSlog(attrs)...)
			logger.LogAttrs(r.Request.Context(), slog.LevelInfo,
				fmt.Sprintf("INCOMING_RESPONSE: %s %s %d%s", r.Request.Method, requestURL, r.StatusCode(), logAttrsSuffix(attrs)),
				logAttrs...,
			)
			return nil
		})
	}
}
