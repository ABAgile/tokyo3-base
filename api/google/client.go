package google

import (
	"context"
	"net/http"

	"github.com/abagile/tokyo3-base/api"
)

const (
	geocodeURL = "https://maps.googleapis.com/maps/api/geocode/json"
	placesURL  = "https://places.googleapis.com/v1/places:searchText"
)

type Client struct {
	rc *api.RestyClient
}

func NewClient(opts ...api.RestyClientOption) *Client {
	return &Client{rc: api.NewRestClient("", opts...)}
}

func (c *Client) Geocode(ctx context.Context, result any, opts ...api.RestyRequestOption) error {
	return c.rc.R(ctx, http.MethodGet, geocodeURL, result, opts...)
}

func (c *Client) SearchPlaces(ctx context.Context, result any, opts ...api.RestyRequestOption) error {
	return c.rc.R(ctx, http.MethodPost, placesURL, result, opts...)
}
