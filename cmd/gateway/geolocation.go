package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/geolocation"
	"github.com/skaldhall/ratatoskr/pkg/observability"
	"golang.org/x/sys/unix"
)

func geolocationInterval(value string) (time.Duration, error) {
	if value == "" {
		return time.Minute, nil
	}
	interval, err := time.ParseDuration(value)
	if err != nil || interval < time.Minute || interval > 24*time.Hour {
		return 0, errors.New("GEOLOCATION_INTERVAL must be 1m..24h")
	}
	return interval, nil
}

// Upstream-bound resolver and HTTP dialer share a socket Control hook: both
// hostname DNS and HTTPS use the gateway's upstream0/interface marked route.
// If either socket option fails, the request fails; there is no direct fallback.
func geoSocketControl(_, _ string, raw syscall.RawConn) error {
	var sockErr error
	err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, datapath.UpstreamDevice)
		if sockErr == nil {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(datapath.ProbeMark))
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}
func newGeolocationClient() (*http.Client, *http.Transport) {
	resolverDialer := &net.Dialer{Timeout: 4 * time.Second, Control: geoSocketControl}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return resolverDialer.DialContext(ctx, network, address)
	}}
	dialer := &net.Dialer{Timeout: 4 * time.Second, Control: geoSocketControl, Resolver: resolver}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 4 * time.Second, MaxIdleConns: 3, MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, transport
}

func startGeolocation(ctx context.Context, snapshot geolocation.ExitSnapshot) (*observability.GeoCollector, error) {
	enabled, err := observability.MetricsEnabled(os.Getenv("GEOLOCATION_ENABLED"))
	if err != nil {
		return nil, fmt.Errorf("GEOLOCATION_ENABLED: %w", err)
	}
	if !enabled {
		return nil, nil
	}
	interval, err := geolocationInterval(strings.TrimSpace(os.Getenv("GEOLOCATION_INTERVAL")))
	if err != nil {
		return nil, err
	}
	client, transport := newGeolocationClient()
	sampler := geolocation.NewSampler(snapshot, func(ctx context.Context, provider geolocation.Provider, ip netip.Addr) (geolocation.Result, time.Duration, error) {
		return geolocation.Lookup(ctx, client, provider, ip)
	}, interval)
	go func() { defer transport.CloseIdleConnections(); sampler.Run(ctx) }()
	return &observability.GeoCollector{Sampler: sampler}, nil
}
