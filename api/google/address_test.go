package google

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/abagile/tokyo3-base/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// redirectTransport rewrites every request to target the given test server,
// allowing tests to intercept calls made to hardcoded external URLs.
type redirectTransport struct{ target string }

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	u, _ := url.Parse(t.target)
	r2.URL.Scheme, r2.URL.Host = u.Scheme, u.Host
	return http.DefaultTransport.RoundTrip(r2)
}

func withTestServer(srv *httptest.Server) api.RestyClientOption {
	return api.CO.WithTransport(&redirectTransport{target: srv.URL})
}

func TestAddressComponent_Name(t *testing.T) {
	testCases := []struct {
		name     string
		comp     AddressComponent
		expected string
	}{
		{
			name:     "LongName takes priority over LongText",
			comp:     AddressComponent{LongName: "Tokyo", LongText: "Tokyo Metropolitan"},
			expected: "Tokyo",
		},
		{
			name:     "falls back to LongText when LongName is empty",
			comp:     AddressComponent{LongText: "Tokyo Metropolitan"},
			expected: "Tokyo Metropolitan",
		},
		{
			name:     "empty when both are empty",
			comp:     AddressComponent{},
			expected: "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.comp.Name())
		})
	}
}

func TestExtractFirstOfCities(t *testing.T) {
	testCases := []struct {
		name       string
		components []AddressComponent
		expected   string
	}{
		{
			name: "locality preferred over administrative_area_level_1",
			components: []AddressComponent{
				{LongName: "Shinjuku", Types: []string{"locality"}},
				{LongName: "Tokyo", Types: []string{"administrative_area_level_1"}},
			},
			expected: "Shinjuku",
		},
		{
			name: "falls back to administrative_area_level_1",
			components: []AddressComponent{
				{LongName: "Tokyo", Types: []string{"administrative_area_level_1"}},
				{LongName: "Japan", Types: []string{"country"}},
			},
			expected: "Tokyo",
		},
		{
			name: "uses LongText when LongName is empty",
			components: []AddressComponent{
				{LongText: "Shibuya", Types: []string{"locality"}},
			},
			expected: "Shibuya",
		},
		{
			name: "returns empty when no priority type found",
			components: []AddressComponent{
				{LongName: "Japan", Types: []string{"country"}},
			},
			expected: "",
		},
		{
			name:       "returns empty for nil components",
			components: nil,
			expected:   "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, extractFirstOfCities(tc.components))
		})
	}
}

func TestGeocodeService_GetResults(t *testing.T) {
	testCases := []struct {
		name       string
		statusCode int
		serverBody string
		wantErr    bool
		expected   []AddressResult
	}{
		{
			name:       "maps response to AddressResults",
			statusCode: http.StatusOK,
			serverBody: `{"results":[{"formatted_address":"Shinjuku, Tokyo","address_components":[{"long_name":"Shinjuku","types":["locality"]}]}]}`,
			expected:   []AddressResult{{Address: "Shinjuku, Tokyo", City: "Shinjuku"}},
		},
		{
			name:       "empty results list",
			statusCode: http.StatusOK,
			serverBody: `{"results":[]}`,
			expected:   []AddressResult{},
		},
		{
			name:       "API error is propagated",
			statusCode: http.StatusUnauthorized,
			serverBody: `{}`,
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				fmt.Fprint(w, tc.serverBody)
			}))
			defer srv.Close()

			svc := NewGeocodeService("test-key", withTestServer(srv))
			results, err := svc.GetResults(context.Background(), "Shinjuku Tokyo")

			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, results)
		})
	}
}

func TestPlacesService_GetResults(t *testing.T) {
	testCases := []struct {
		name       string
		statusCode int
		serverBody string
		wantErr    bool
		expected   []AddressResult
	}{
		{
			name:       "maps response to AddressResults",
			statusCode: http.StatusOK,
			serverBody: `{"places":[{"formattedAddress":"Shibuya, Tokyo","addressComponents":[{"longText":"Shibuya","types":["locality"]}]}]}`,
			expected:   []AddressResult{{Address: "Shibuya, Tokyo", City: "Shibuya"}},
		},
		{
			name:       "empty places list",
			statusCode: http.StatusOK,
			serverBody: `{"places":[]}`,
			expected:   []AddressResult{},
		},
		{
			name:       "API error is propagated",
			statusCode: http.StatusForbidden,
			serverBody: `{}`,
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				fmt.Fprint(w, tc.serverBody)
			}))
			defer srv.Close()

			svc := NewPlacesService("test-key", withTestServer(srv))
			results, err := svc.GetResults(context.Background(), "Shibuya Tokyo")

			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, results)
		})
	}
}
