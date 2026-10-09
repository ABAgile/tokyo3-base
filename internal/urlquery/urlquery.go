// Package urlquery adds query parameters to an endpoint URL that may already
// carry its own query string, such as an IdP authorize URL with a tenant
// selector.
package urlquery

import (
	"maps"
	"net/url"
)

// Merge returns endpoint with params added to its query. The endpoint's
// existing parameters are kept, and a parameter named in params replaces the
// endpoint's value, so protocol parameters such as client_id always come from
// the caller.
func Merge(endpoint string, params url.Values) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	maps.Copy(q, params)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
