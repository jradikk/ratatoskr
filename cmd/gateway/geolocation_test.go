package main

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/skaldhall/ratatoskr/pkg/geolocation"
)

func TestGeoConfigAndDisabledCollector(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  time.Duration
		fail  bool
	}{
		{"", time.Minute, false}, {"1m", time.Minute, false}, {"24h", 24 * time.Hour, false}, {"59s", 0, true}, {"25h", 0, true}, {"bad", 0, true},
	} {
		got, err := geolocationInterval(tc.input)
		if got != tc.want || (err != nil) != tc.fail {
			t.Fatalf("interval %q got=%s err=%v", tc.input, got, err)
		}
	}
	t.Setenv("GEOLOCATION_ENABLED", "false")
	t.Setenv("GEOLOCATION_INTERVAL", "not a duration")
	collector, err := startGeolocation(context.Background(), func() (netip.Addr, bool) { return netip.Addr{}, false })
	if err != nil || collector != nil {
		t.Fatalf("disabled geolocation started collector=%v err=%v", collector, err)
	}
}
func TestGeoProviderFixedNames(t *testing.T) {
	if len(geolocation.Providers) != 3 || geolocation.Providers[0] != "freeipapi" || geolocation.Providers[1] != "geojs" || geolocation.Providers[2] != "ipwhois" {
		t.Fatal(geolocation.Providers)
	}
}

func TestGeoSocketControlRejectsMissingUpstream(t *testing.T) {
	// This checks the real option setter independently of any external network.
	// Only a disposable namespace with no upstream0 can assert ENODEV.
	if _, err := net.InterfaceByName("upstream0"); err == nil {
		t.Skip("upstream0 exists in this namespace")
	}
	dialer := &net.Dialer{Control: geoSocketControl, Timeout: time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp4", "127.0.0.1:1")
	if conn != nil {
		conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "no such device") {
		t.Fatalf("missing upstream0 must fail closed, got %v", err)
	}
}
