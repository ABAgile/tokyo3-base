// Package api is a thin, typed layer over the Resty HTTP client: functional
// client and request options, a typed APIError for non-2xx responses, bounded
// error bodies, a concurrency-safe bearer-token cache with refresh, and a
// redacting request/response logger.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

type contextKey string

type RestyClient struct {
	*resty.Client
}

type ClientOption struct{}

var CO ClientOption

type RequestOption struct{}

var RO RequestOption

type RestyClientOption func(*resty.Client)
type RestyRequestOption func(*resty.Request)

// defaultTimeout bounds each request made through NewRestClient unless the
// caller sets CO.WithTimeout. It covers the whole exchange, body included.
const defaultTimeout = 30 * time.Second

func NewRestClient(baseURL string, opts ...RestyClientOption) *RestyClient {
	client := resty.New().SetBaseURL(baseURL).SetTimeout(defaultTimeout).SetLogger(newRestyLogger(sanitizeURL))
	for _, opt := range opts {
		opt(client)
	}
	// Bound error reads before Resty buffers or logs them. Success responses
	// remain unlimited, and custom transports configured by options survive.
	client.GetClient().Transport = errorBodyTransport{base: client.GetClient().Transport}
	return &RestyClient{Client: client}
}

func (co *ClientOption) WithBaseURL(url string) RestyClientOption {
	return func(c *resty.Client) {
		c.SetBaseURL(url)
	}
}

func (co *ClientOption) WithTimeout(timeout time.Duration) RestyClientOption {
	return func(c *resty.Client) {
		c.SetTimeout(timeout)
	}
}

func (co *ClientOption) WithRetryCount(count int) RestyClientOption {
	return func(c *resty.Client) {
		c.SetRetryCount(count)
	}
}

// WithDebug turns on Resty's built-in debug output. It prints the full request
// URL (including query-string credentials such as API keys), every header
// including Authorization, and bodies, none of it redacted. Use it only for
// local troubleshooting; production logging belongs to [ClientOption.WithRequestLogger].
func (co *ClientOption) WithDebug(d bool) RestyClientOption {
	return func(c *resty.Client) {
		c.SetDebug(d)
	}
}

func (co *ClientOption) WithHeader(key, value string) RestyClientOption {
	return func(c *resty.Client) {
		c.SetHeader(key, value)
	}
}

func (co *ClientOption) WithHeaders(headers map[string]string) RestyClientOption {
	return func(c *resty.Client) { c.SetHeaders(headers) }
}

func (co *ClientOption) WithAuthToken(token string) RestyClientOption {
	return func(c *resty.Client) {
		c.SetAuthToken(token)
	}
}

func (co *ClientOption) WithBasicAuth(username, password string) RestyClientOption {
	return func(c *resty.Client) {
		c.SetBasicAuth(username, password)
	}
}

func (co *ClientOption) WithTransport(rt http.RoundTripper) RestyClientOption {
	return func(c *resty.Client) {
		c.SetTransport(rt)
	}
}

// ErrNotModified is returned by [RestyClient.R] for a 304 response. A 304
// answers a conditional request (If-None-Match or If-Modified-Since) whose
// validator still matches, so the caller's cached copy is current. That is
// not a failure; test for it with errors.Is. Every other non-2xx status is
// an [APIError].
var ErrNotModified = errors.New("api: not modified")

// APIError is the typed error returned by [RestyClient.R] for non-2xx
// responses other than 304 (see [ErrNotModified]). StatusCode is the HTTP status. Body is the raw response
// body — captured verbatim so callers can surface server-side error
// messages in their own error chains without doing a second
// roundtrip. Body is truncated at 64 KiB to bound memory; servers
// that need to communicate larger error payloads should use a
// structured error contract instead.
type APIError struct {
	StatusCode int
	Body       []byte
}

// apiErrorBodyTruncate caps the Body inline in the Error() string so
// a verbose server response doesn't blow out log lines. Full bytes
// remain available via e.Body for callers that want them.
const apiErrorBodyTruncate = 512

func (e *APIError) Error() string {
	body := strings.TrimSpace(string(e.Body))
	if body == "" {
		return fmt.Sprintf("api error: status %d", e.StatusCode)
	}
	if len(body) > apiErrorBodyTruncate {
		body = body[:apiErrorBodyTruncate] + "..."
	}
	return fmt.Sprintf("api error: status %d: %s", e.StatusCode, body)
}

func (rc *RestyClient) R(ctx context.Context, method, path string, result any, opts ...RestyRequestOption) error {
	req := rc.Client.R().SetContext(ctx)
	// Resty logs transport errors, including every retry attempt, before they
	// reach this function. Redact with this request's path params as well,
	// including client-level and raw ones.
	req.SetLogger(newRestyLogger(func(raw string) string {
		return sanitizeRequestURL(raw, requestPathParams(rc.Client, req))
	}))
	for _, opt := range opts {
		opt(req)
	}
	resp, err := req.Execute(method, path)
	if err != nil {
		// net/http embeds the full request URL in its error; scrub credential
		// query and path parameters (API keys, tokens) before it reaches logs
		// or callers.
		if ue, ok := errors.AsType[*url.Error](err); ok {
			ue.URL = sanitizeRequestURL(ue.URL, requestPathParams(rc.Client, req))
		}
		return fmt.Errorf("api call failed: %w", err)
	}
	if resp.StatusCode() == http.StatusNotModified {
		return ErrNotModified
	}
	// Anything else outside 2xx is an error, including 3xx responses that were
	// not followed (for example under a no-redirect policy).
	if !resp.IsSuccess() {
		body := resp.Body()
		// Also enforce the retained-body contract if a caller replaced the
		// embedded Resty client's transport after construction.
		if len(body) > apiErrorBodyLimit {
			body = slices.Clone(body[:apiErrorBodyLimit])
		}
		return &APIError{StatusCode: resp.StatusCode(), Body: body}
	}
	// Decode the response body into result manually rather than via
	// Resty's SetResult — that auto-decode hinges on the server
	// sending Content-Type: application/json, which our internal
	// test mocks frequently omit and our hand-rolled clients
	// historically never required. Empty body + result is a no-op
	// (matches "I don't care about the body" callers passing
	// &struct{}{}); nil result also short-circuits.
	body := resp.Body()
	if len(body) == 0 || result == nil {
		return nil
	}
	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("api call failed: decode response: %w", err)
	}
	return nil
}

// WithDebug enables Resty's unredacted debug output for one request; see
// [ClientOption.WithDebug] for what it exposes.
func (ro *RequestOption) WithDebug(d bool) RestyRequestOption {
	return func(r *resty.Request) {
		r.SetDebug(d)
	}
}

func (ro *RequestOption) WithPathParam(param, value string) RestyRequestOption {
	return func(r *resty.Request) {
		r.SetPathParam(param, value)
	}
}

func (ro *RequestOption) WithPathParams(params map[string]string) RestyRequestOption {
	return func(r *resty.Request) {
		r.SetPathParams(params)
	}
}

func (ro *RequestOption) WithQueryParam(param, value string) RestyRequestOption {
	return func(r *resty.Request) {
		r.SetQueryParam(param, value)
	}
}

func (ro *RequestOption) WithQueryParams(params map[string]string) RestyRequestOption {
	return func(r *resty.Request) {
		r.SetQueryParams(params)
	}
}

func (ro *RequestOption) WithBody(body any) RestyRequestOption {
	return func(r *resty.Request) {
		r.SetBody(body)
	}
}

func (ro *RequestOption) WithHeader(key, value string) RestyRequestOption {
	return func(r *resty.Request) {
		r.SetHeader(key, value)
	}
}

func (ro *RequestOption) WithHeaders(headers map[string]string) RestyRequestOption {
	return func(r *resty.Request) { r.SetHeaders(headers) }
}

func (ro *RequestOption) WithAuthToken(token string) RestyRequestOption {
	return func(r *resty.Request) {
		r.SetAuthToken(token)
	}
}

func (ro *RequestOption) WithBasicAuth(username, password string) RestyRequestOption {
	return func(r *resty.Request) {
		r.SetBasicAuth(username, password)
	}
}
