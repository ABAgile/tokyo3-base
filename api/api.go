package api

import (
	"context"
	"fmt"
	"net/http"
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

type ApiError struct {
	StatusCode int
}

func (e *ApiError) Error() string {
	return fmt.Sprintf("api error: status %d", e.StatusCode)
}

func (rc *RestyClient) R(ctx context.Context, method, path string, result any, opts ...RestyRequestOption) error {
	req := rc.Client.R().SetContext(ctx).SetResult(result).SetError(result)
	for _, opt := range opts {
		opt(req)
	}
	resp, err := req.Execute(method, path)
	if err != nil {
		return fmt.Errorf("api call failed: %w", err)
	}
	if resp.IsError() {
		return &ApiError{StatusCode: resp.StatusCode()}
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
