// Package geolocation samples token-free public geolocation providers for a
// verified gateway exit IP. Coordinates are approximate provider estimates.
package geolocation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Provider is one fixed public HTTPS API. Callers cannot supply arbitrary URLs.
type Provider string

const (
	FreeIPAPI Provider = "freeipapi"
	GeoJS     Provider = "geojs"
	IPWhoIs   Provider = "ipwhois"
)

var Providers = []Provider{FreeIPAPI, GeoJS, IPWhoIs}

// Result only contains public response data after exact requested-IP validation.
type Result struct {
	IP                  netip.Addr
	Latitude, Longitude float64
	Country, City       string
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func endpoint(provider Provider, ip netip.Addr) (string, error) {
	if !ip.Is4() || ip.IsUnspecified() {
		return "", errors.New("geolocation requires a valid exit IPv4")
	}
	switch provider {
	case FreeIPAPI:
		return "https://free.freeipapi.com/api/v1/json/" + ip.String(), nil
	case GeoJS:
		return "https://get.geojs.io/v1/ip/geo/" + ip.String() + ".json", nil
	case IPWhoIs:
		return "https://ipwho.is/" + ip.String(), nil
	default:
		return "", errors.New("unknown geolocation provider")
	}
}
func parseResult(provider Provider, reader io.Reader, requested netip.Addr) (Result, error) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(reader, 16<<10)).Decode(&raw); err != nil {
		return Result{}, err
	}
	ipKey, latKey, lonKey, countryKey, cityKey := "ip", "latitude", "longitude", "country_code", "city"
	switch provider {
	case FreeIPAPI:
		ipKey, countryKey, cityKey = "ipAddress", "countryCode", "cityName"
	case GeoJS:
	case IPWhoIs:
	default:
		return Result{}, errors.New("unsupported geolocation provider")
	}
	getString := func(key string) string { var s string; _ = json.Unmarshal(raw[key], &s); return s }
	actual, err := netip.ParseAddr(getString(ipKey))
	if err != nil || actual != requested {
		return Result{}, errors.New("geolocation response IP mismatch")
	}
	if provider == IPWhoIs {
		if getString("type") != "IPv4" {
			return Result{}, errors.New("provider IP type mismatch")
		}
		var success bool
		if err := json.Unmarshal(raw["success"], &success); err != nil || !success {
			return Result{}, errors.New("provider geolocation lookup failed")
		}
	}
	if provider == FreeIPAPI {
		var version int
		if err := json.Unmarshal(raw["ipVersion"], &version); err != nil || version != 4 {
			return Result{}, errors.New("provider IP version mismatch")
		}
	}
	coordinate := func(key string) (float64, error) {
		val, present := raw[key]
		if !present || string(val) == "null" {
			return 0, errors.New("missing coordinate")
		}
		var number float64
		if provider == GeoJS {
			number, err = strconv.ParseFloat(getString(key), 64)
		} else {
			err = json.Unmarshal(val, &number)
		}
		if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
			return 0, errors.New("invalid coordinate")
		}
		return number, nil
	}
	lat, err := coordinate(latKey)
	if err != nil || lat < -90 || lat > 90 {
		return Result{}, errors.New("invalid latitude")
	}
	lon, err := coordinate(lonKey)
	if err != nil || lon < -180 || lon > 180 {
		return Result{}, errors.New("invalid longitude")
	}
	clean := func(value string) string {
		value = strings.ToValidUTF8(value, "")
		value = strings.Map(func(r rune) rune {
			if r < 32 || r == 127 || r == '\ufffd' {
				return -1
			}
			return r
		}, value)
		if len(value) > 64 {
			value = value[:64]
			value = strings.ToValidUTF8(value, "")
		}
		return value
	}
	country, city := clean(getString(countryKey)), clean(getString(cityKey))
	if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return Result{}, errors.New("invalid country code")
	}
	return Result{IP: actual, Latitude: lat, Longitude: lon, Country: country, City: city}, nil
}

// Lookup performs a single exact-IP HTTPS request. Client controls socket
// routing and has its own timeout; redirects are refused by the gateway client.
func Lookup(ctx context.Context, client HTTPDoer, provider Provider, ip netip.Addr) (Result, time.Duration, error) {
	address, err := endpoint(provider, ip)
	if err != nil {
		return Result{}, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return Result{}, 0, err
	}
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return Result{}, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		var wait time.Duration
		if response.StatusCode == http.StatusTooManyRequests {
			if seconds, e := strconv.Atoi(response.Header.Get("Retry-After")); e == nil && seconds > 0 && seconds <= 86400 {
				wait = time.Duration(seconds) * time.Second
			}
		}
		return Result{}, wait, fmt.Errorf("geolocation HTTP status %d", response.StatusCode)
	}
	result, err := parseResult(provider, response.Body, ip)
	return result, 0, err
}
