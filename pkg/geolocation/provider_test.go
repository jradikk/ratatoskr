package geolocation

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }
func TestProviderLookupsRequireExactIPAndBoundedFields(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, tc := range []struct {
		provider  Provider
		body, url string
	}{
		{FreeIPAPI, `{"ipAddress":"8.8.8.8","ipVersion":4,"latitude":37.4,"longitude":-122.0,"countryCode":"US","cityName":"Palo Alto"}`, "https://free.freeipapi.com/api/v1/json/8.8.8.8"},
		{GeoJS, `{"ip":"8.8.8.8","latitude":"37.4","longitude":"-122.0","country_code":"US","city":"Palo Alto"}`, "https://get.geojs.io/v1/ip/geo/8.8.8.8.json"},
		{IPWhoIs, `{"success":true,"type":"IPv4","ip":"8.8.8.8","latitude":37.4,"longitude":-122.0,"country_code":"US","city":"Palo Alto"}`, "https://ipwho.is/8.8.8.8"},
	} {
		t.Run(string(tc.provider), func(t *testing.T) {
			doer := doerFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() != tc.url || req.Method != http.MethodGet || req.Header.Get("Accept") != "application/json" {
					t.Fatalf("bad request: %+v", req)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			result, wait, err := Lookup(context.Background(), doer, tc.provider, ip)
			if err != nil || wait != 0 || result.IP != ip || result.Country != "US" || result.City != "Palo Alto" || result.Latitude != 37.4 || result.Longitude != -122.0 {
				t.Fatalf("result=%+v wait=%s err=%v", result, wait, err)
			}
			body := strings.Replace(tc.body, "8.8.8.8", "1.1.1.1", 1)
			if _, err := parseResult(tc.provider, strings.NewReader(body), ip); err == nil {
				t.Fatal("accepted response for different IP")
			}
		})
	}
	for _, tc := range []struct {
		provider Provider
		body     string
	}{
		{FreeIPAPI, `{"ipVersion":6,"ipAddress":"8.8.8.8","latitude":4,"longitude":5,"countryCode":"US"}`},
		{GeoJS, `{"ip":"8.8.8.8","latitude":"NaN","longitude":"1","country_code":"US"}`},
		{IPWhoIs, `{"success":false,"type":"IPv4","ip":"8.8.8.8","latitude":1,"longitude":1,"country_code":"US"}`},
		{IPWhoIs, `{"success":true,"type":"IPv4","ip":"8.8.8.8","latitude":91,"longitude":1,"country_code":"US"}`},
	} {
		if _, err := parseResult(tc.provider, strings.NewReader(tc.body), ip); err == nil {
			t.Fatalf("accepted malformed %s: %s", tc.provider, tc.body)
		}
	}
	if _, err := endpoint(FreeIPAPI, netip.MustParseAddr("::1")); err == nil {
		t.Fatal("accepted IPv6")
	}
	if _, err := endpoint(Provider("custom"), ip); err == nil {
		t.Fatal("accepted arbitrary endpoint")
	}
}
func TestLookupHonorsRetryAfterAndRefusesErrors(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	doer := doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"300"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	if _, wait, err := Lookup(context.Background(), doer, IPWhoIs, ip); err == nil || wait != 5*time.Minute {
		t.Fatalf("retry=%s err=%v", wait, err)
	}
}
