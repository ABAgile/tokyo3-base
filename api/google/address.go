package google

import (
	"context"
	"slices"

	"github.com/abagile/tokyo3-base/api"
)

type Addresser interface {
	GetResults(ctx context.Context, address string) ([]AddressResult, error)
}

type AddressResult struct {
	Address string
	City    string
}

type AddressComponent struct {
	LongName string   `json:"long_name"`
	LongText string   `json:"longText"`
	Types    []string `json:"types"`
}

func (ac AddressComponent) Name() string {
	if ac.LongName != "" {
		return ac.LongName
	}
	return ac.LongText
}

type geocodeResponse struct {
	Results []struct {
		FormattedAddress  string             `json:"formatted_address"`
		AddressComponents []AddressComponent `json:"address_components"`
	} `json:"results"`
}

type GeocodeService struct {
	client *Client
	apiKey string
}

func NewGeocodeService(apiKey string, opts ...api.RestyClientOption) Addresser {
	return &GeocodeService{client: NewClient(opts...), apiKey: apiKey}
}

func (s *GeocodeService) GetResults(ctx context.Context, address string) ([]AddressResult, error) {
	var res geocodeResponse
	if err := s.client.Geocode(ctx, &res, api.RO.WithQueryParams(map[string]string{
		"key":     s.apiKey,
		"address": address,
	})); err != nil {
		return nil, err
	}
	results := make([]AddressResult, 0, len(res.Results))
	for _, r := range res.Results {
		results = append(results, AddressResult{
			Address: r.FormattedAddress,
			City:    extractFirstOfCities(r.AddressComponents),
		})
	}
	return results, nil
}

type placesResponse struct {
	Places []struct {
		FormattedAddress  string             `json:"formattedAddress"`
		AddressComponents []AddressComponent `json:"addressComponents"`
	} `json:"places"`
}

type PlacesService struct {
	client *Client
	apiKey string
}

func NewPlacesService(apiKey string, opts ...api.RestyClientOption) Addresser {
	return &PlacesService{client: NewClient(opts...), apiKey: apiKey}
}

func (s *PlacesService) GetResults(ctx context.Context, address string) ([]AddressResult, error) {
	var res placesResponse
	if err := s.client.SearchPlaces(ctx, &res,
		api.RO.WithHeaders(map[string]string{"X-Goog-Api-Key": s.apiKey, "X-Goog-FieldMask": "*"}),
		api.RO.WithBody(map[string]string{"textQuery": address}),
	); err != nil {
		return nil, err
	}
	results := make([]AddressResult, 0, len(res.Places))
	for _, pl := range res.Places {
		results = append(results, AddressResult{
			Address: pl.FormattedAddress,
			City:    extractFirstOfCities(pl.AddressComponents),
		})
	}
	return results, nil
}

var typePriority = []string{"locality", "administrative_area_level_1"}

func extractFirstOfCities(components []AddressComponent) string {
	for _, t := range typePriority {
		for _, m := range components {
			if slices.Contains(m.Types, t) {
				if name := m.Name(); name != "" {
					return name
				}
			}
		}
	}
	return ""
}
