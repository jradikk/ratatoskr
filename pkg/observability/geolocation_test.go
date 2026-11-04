package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/skaldhall/ratatoskr/pkg/geolocation"
)

func TestGeoCollectorCoordinatesDriftFailureAndRevocation(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	ready := true
	sampler := geolocation.NewSampler(func() (netip.Addr, bool) { return ip, ready }, func(_ context.Context, p geolocation.Provider, asked netip.Addr) (geolocation.Result, time.Duration, error) {
		lat := 10.0
		if p == geolocation.GeoJS {
			lat = 11
		}
		return geolocation.Result{IP: asked, Latitude: lat, Longitude: 20, Country: "US", City: "Test"}, 0, nil
	}, time.Minute)
	registry := prometheus.NewRegistry()
	registry.MustRegister(&GeoCollector{Sampler: sampler})
	scrape := func() string {
		rec := httptest.NewRecorder()
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("bad scrape %d: %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	initial := scrape()
	if !strings.Contains(initial, "ratatoskr_gateway_geolocation_lookup_success{exit_ip=\"8.8.8.8\",provider=\"ipwhois\"} 0") || strings.Contains(initial, "ratatoskr_gateway_geolocation_latitude_degrees{") {
		t.Fatal(initial)
	}
	sampler.Step(context.Background())
	text := scrape()
	for _, v := range []string{`ratatoskr_gateway_geolocation_lookup_success{exit_ip="8.8.8.8",provider="ipwhois"} 1`, `ratatoskr_gateway_geolocation_latitude_degrees{exit_ip="8.8.8.8",provider="geojs"} 11`, `ratatoskr_gateway_geolocation_info{city="Test",country="US",exit_ip="8.8.8.8",provider="freeipapi"} 1`, `ratatoskr_gateway_geolocation_distance_meters{exit_ip="8.8.8.8",provider_a="freeipapi",provider_b="geojs"}`} {
		if !strings.Contains(text, v) {
			t.Fatalf("missing %s in %s", v, text)
		}
	}
	ip = netip.MustParseAddr("1.1.1.1")
	text = scrape()
	if strings.Contains(text, "8.8.8.8") || strings.Contains(text, "ratatoskr_gateway_geolocation_distance_meters{") {
		t.Fatalf("old coordinates leaked after exit switch: %s", text)
	}
	ready = false
	if text = scrape(); strings.Contains(text, "ratatoskr_gateway_geolocation_latitude_degrees{") {
		t.Fatalf("unhealthy gateway leaked coords: %s", text)
	}
}
func TestGeoDistanceMeters(t *testing.T) {
	if distanceMeters(0, 0, 0, 0) != 0 {
		t.Fatal("identical coordinates differ")
	}
	got := distanceMeters(0, 0, 0, 1)
	if got < 111000 || got > 112000 {
		t.Fatalf("unexpected great-circle 1 degree distance %v", got)
	}
}
