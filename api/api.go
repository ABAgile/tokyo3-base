package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

func NewRestClient(baseURL string, opts ...RestyClientOption) *RestyClient {
	client := resty.New().SetBaseURL(baseURL)
	for _, opt := range opts {
		opt(client)
	}
	return &RestyClient{Client: client}
}

func (co *ClientOption) WithBaseUrl(url string) RestyClientOption {
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

// ApiError is the typed error returned by [RestyClient.R] for non-2xx
// responses. StatusCode is the HTTP status. Body is the raw response
// body — captured verbatim so callers can surface server-side error
// messages in their own error chains without doing a second
// roundtrip. Body is truncated at 64 KiB to bound memory; servers
// that need to communicate larger error payloads should use a
// structured error contract instead.
type ApiError struct {
	StatusCode int
	Body       []byte
}

// apiErrorBodyTruncate caps the Body inline in the Error() string so
// a verbose server response doesn't blow out log lines. Full bytes
// remain available via e.Body for callers that want them.
const apiErrorBodyTruncate = 512

func (e *ApiError) Error() string {
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
	for _, opt := range opts {
		opt(req)
	}
	resp, err := req.Execute(method, path)
	if err != nil {
		return fmt.Errorf("api call failed: %w", err)
	}
	if resp.IsError() {
		return &ApiError{StatusCode: resp.StatusCode(), Body: resp.Body()}
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
