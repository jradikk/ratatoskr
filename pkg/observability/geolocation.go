package observability

import (
	"math"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/skaldhall/ratatoskr/pkg/geolocation"
)

// GeoCollector only reads cached, validated samples; it never makes a network
// request on a scrape and never influences the gateway's health state.
type GeoCollector struct{ Sampler *geolocation.Sampler }

var (
	geoSuccess   = prometheus.NewDesc("ratatoskr_gateway_geolocation_lookup_success", "1 if the most recent lookup for current exit IP succeeded and remains fresh; 0 if unknown or failed.", []string{"provider", "exit_ip"}, nil)
	geoLatitude  = prometheus.NewDesc("ratatoskr_gateway_geolocation_latitude_degrees", "Recent provider latitude for current gateway exit IPv4.", []string{"provider", "exit_ip"}, nil)
	geoLongitude = prometheus.NewDesc("ratatoskr_gateway_geolocation_longitude_degrees", "Recent provider longitude for current gateway exit IPv4.", []string{"provider", "exit_ip"}, nil)
	geoInfo      = prometheus.NewDesc("ratatoskr_gateway_geolocation_info", "Bounded public country and city for current validated gateway exit IPv4.", []string{"provider", "exit_ip", "country", "city"}, nil)
	geoLast      = prometheus.NewDesc("ratatoskr_gateway_geolocation_last_success_timestamp_seconds", "Unix timestamp of last valid lookup for current exit IPv4.", []string{"provider", "exit_ip"}, nil)
	geoAge       = prometheus.NewDesc("ratatoskr_gateway_geolocation_age_seconds", "Seconds since last valid lookup for current exit IPv4.", []string{"provider", "exit_ip"}, nil)
	geoFailures  = prometheus.NewDesc("ratatoskr_gateway_geolocation_failures_total", "Process-lifetime failed geolocation lookups by fixed provider.", []string{"provider"}, nil)
	geoDistance  = prometheus.NewDesc("ratatoskr_gateway_geolocation_distance_meters", "Great-circle distance between recent vendor coordinate estimates for the same current exit IP; geolocation is approximate.", []string{"provider_a", "provider_b", "exit_ip"}, nil)
)

func (c *GeoCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{geoSuccess, geoLatitude, geoLongitude, geoInfo, geoLast, geoAge, geoFailures, geoDistance} {
		ch <- d
	}
}
func (c *GeoCollector) Collect(ch chan<- prometheus.Metric) {
	if c == nil || c.Sampler == nil {
		return
	}
	statuses := c.Sampler.Current()
	for _, s := range statuses {
		p := string(s.Provider)
		ch <- prometheus.MustNewConstMetric(geoFailures, prometheus.CounterValue, float64(s.Failures), p)
		ip := ""
		if s.ExitIP.Is4() {
			ip = s.ExitIP.String()
		}
		ok := float64(0)
		if s.OK {
			ok = 1
		}
		ch <- prometheus.MustNewConstMetric(geoSuccess, prometheus.GaugeValue, ok, p, ip)
		if s.LastSuccess.IsZero() || !s.ExitIP.Is4() {
			continue
		}
		age := time.Since(s.LastSuccess).Seconds()
		if age < 0 {
			age = 0
		}
		ch <- prometheus.MustNewConstMetric(geoLast, prometheus.GaugeValue, float64(s.LastSuccess.Unix()), p, ip)
		ch <- prometheus.MustNewConstMetric(geoAge, prometheus.GaugeValue, age, p, ip)
		if !s.OK {
			continue
		} // preserve last-success metadata, never publish failed lookup coordinates
		ch <- prometheus.MustNewConstMetric(geoLatitude, prometheus.GaugeValue, s.Result.Latitude, p, ip)
		ch <- prometheus.MustNewConstMetric(geoLongitude, prometheus.GaugeValue, s.Result.Longitude, p, ip)
		ch <- prometheus.MustNewConstMetric(geoInfo, prometheus.GaugeValue, 1, p, ip, s.Result.Country, s.Result.City)
	}
	for i, a := range statuses {
		if a.LastSuccess.IsZero() || !a.ExitIP.Is4() || !a.OK {
			continue
		}
		for _, b := range statuses[i+1:] {
			if b.LastSuccess.IsZero() || b.ExitIP != a.ExitIP || !b.OK {
				continue
			}
			ch <- prometheus.MustNewConstMetric(geoDistance, prometheus.GaugeValue, distanceMeters(a.Result.Latitude, a.Result.Longitude, b.Result.Latitude, b.Result.Longitude), string(a.Provider), string(b.Provider), a.ExitIP.String())
		}
	}
}
func distanceMeters(latA, lonA, latB, lonB float64) float64 {
	const radius = 6371008.8
	rad := math.Pi / 180
	dlat := (latB - latA) * rad
	dlon := (lonB - lonA) * rad
	a := math.Pow(math.Sin(dlat/2), 2) + math.Cos(latA*rad)*math.Cos(latB*rad)*math.Pow(math.Sin(dlon/2), 2)
	return 2 * radius * math.Asin(math.Sqrt(math.Min(1, math.Max(0, a))))
}

var _ prometheus.Collector = (*GeoCollector)(nil)
