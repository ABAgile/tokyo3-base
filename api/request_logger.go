package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"sort"
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

func sortedKeys(attrs map[string]string) []string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func logAttrsSuffix(attrs map[string]string) string {
	if len(attrs) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(" |>>")
	for _, k := range sortedKeys(attrs) {
		fmt.Fprintf(&sb, " %s: [%s]", k, attrs[k])
	}
	return sb.String()
}

func logAttrsToSlog(attrs map[string]string) []slog.Attr {
	if len(attrs) == 0 {
		return nil
	}
	keys := sortedKeys(attrs)
	result := make([]slog.Attr, len(keys))
	for i, k := range keys {
		result[i] = slog.String(k, attrs[k])
	}
	return result
}

func SanitizeHeaders(h map[string][]string) map[string][]string {
	safe := make(map[string][]string, len(h))
	for k, v := range h {
		key := strings.ToLower(k)
		if key == "authorization" || key == "cookie" {
			safe[k] = []string{"***redacted***"}
		} else {
			safe[k] = v
		}
	}
	return safe
}

func (co *ClientOption) WithRequestLogger(logger *slog.Logger) RestyClientOption {
	return func(c *resty.Client) {
		if logger == nil {
			logger = slog.Default()
		}
		// setup send log
		c.OnBeforeRequest(func(rc *resty.Client, r *resty.Request) error {
			var bodyStr string
			if r.Body != nil {
				if jb, err := json.Marshal(r.Body); err == nil {
					bodyStr = string(jb)
				}
			}
			fullUrl := r.URL
			queryStr := r.QueryParam.Encode()
			if queryStr != "" {
				fullUrl += "&" + queryStr
			}
			pathParamStr := ""
			if len(r.PathParams) > 0 {
				pathParamStr = fmt.Sprintf("%v", r.PathParams)
				fullUrl += " " + pathParamStr[3:]
			}
			attrs, _ := r.Context().Value(logAttrsKey).(map[string]string)
			logAttrs := append([]slog.Attr{
				slog.String("method", r.Method),
				slog.String("url", r.URL),
				slog.String("queryParam", r.QueryParam.Encode()),
				slog.String("pathParam", pathParamStr),
				slog.Any("header", SanitizeHeaders(r.Header)),
				slog.String("body", bodyStr),
			}, logAttrsToSlog(attrs)...)
			logger.LogAttrs(context.Background(), slog.LevelInfo,
				fmt.Sprintf("OUTGOING_REQUEST: %s %s%s", r.Method, fullUrl, logAttrsSuffix(attrs)),
				logAttrs...,
			)
			return nil
		})

		// setup receive log
		c.OnAfterResponse(func(rc *resty.Client, r *resty.Response) error {
			attrs, _ := r.Request.Context().Value(logAttrsKey).(map[string]string)
			logAttrs := append([]slog.Attr{
				slog.String("method", r.Request.Method),
				slog.String("url", r.Request.URL),
				slog.Int("status", r.StatusCode()),
				slog.Any("header", SanitizeHeaders(r.Header())),
				slog.String("body", string(r.Body())),
				slog.String("elapsed", r.Time().String()),
				slog.Duration("elapsed_ms", r.Time()),
			}, logAttrsToSlog(attrs)...)
			logger.LogAttrs(context.Background(), slog.LevelInfo,
				fmt.Sprintf("INCOMING_RESPONSE: %s %s %d%s", r.Request.Method, r.Request.URL, r.StatusCode(), logAttrsSuffix(attrs)),
				logAttrs...,
			)
			return nil
		})
	}
}
