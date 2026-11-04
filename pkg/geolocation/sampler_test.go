package geolocation

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestSamplerCachesPerProviderAndRevokesChangedExit(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	now := time.Unix(1770000000, 0)
	ready := true
	calls := map[Provider]int{}
	fail := false
	sampler := NewSampler(func() (netip.Addr, bool) { return ip, ready }, func(_ context.Context, provider Provider, asked netip.Addr) (Result, time.Duration, error) {
		calls[provider]++
		if fail {
			return Result{}, 3 * time.Minute, errors.New("rate limit")
		}
		return Result{IP: asked, Latitude: 37, Longitude: -120, Country: "US", City: "Test"}, 0, nil
	}, time.Minute)
	sampler.now = func() time.Time { return now }
	for _, status := range sampler.Current() {
		if status.OK || !status.LastSuccess.IsZero() {
			t.Fatalf("premature sample: %+v", status)
		}
	}
	sampler.Step(context.Background())
	for _, status := range sampler.Current() {
		if !status.OK || status.ExitIP != ip {
			t.Fatalf("missing sample: %+v", status)
		}
	}
	now = now.Add(time.Minute)
	sampler.Step(context.Background())
	if calls[IPWhoIs] != 1 || calls[FreeIPAPI] != 2 || calls[GeoJS] != 2 {
		t.Fatalf("incorrect per-vendor cooldown: %+v", calls)
	}
	fail = true
	now = now.Add(time.Minute)
	sampler.Step(context.Background())
	for _, status := range sampler.Current() {
		if status.OK || status.LastSuccess.IsZero() || status.Result.IP != ip || status.Failures != 1 {
			t.Fatalf("failed lookup lost last-known data or marked healthy: %+v", status)
		}
	}
	ip = netip.MustParseAddr("9.9.9.9")
	for _, status := range sampler.Current() {
		if status.OK || !status.LastSuccess.IsZero() || status.Result.IP.IsValid() {
			t.Fatalf("old exit data leaked after IP change: %+v", status)
		}
	}
	sampler.Step(context.Background())
	for _, status := range sampler.Current() {
		if status.OK || !status.LastSuccess.IsZero() || status.Failures != 1 {
			t.Fatalf("failure on new IP leaked coordinates: %+v", status)
		}
	}
	ip = netip.MustParseAddr("8.8.8.8")
	for _, status := range sampler.Current() {
		if status.OK || !status.LastSuccess.IsZero() || status.Result.IP.IsValid() {
			t.Fatalf("IP reuse resurrected stale coordinates: %+v", status)
		}
	}
	ready = false
	for _, status := range sampler.Current() {
		if status.OK || !status.LastSuccess.IsZero() {
			t.Fatalf("unhealthy exit leaked data: %+v", status)
		}
	}
}
func TestSamplerExpiresCoordinatesAndChecksProviderIP(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	now := time.Now()
	sampler := NewSampler(func() (netip.Addr, bool) { return ip, true }, func(_ context.Context, p Provider, _ netip.Addr) (Result, time.Duration, error) {
		return Result{IP: netip.MustParseAddr("1.1.1.1")}, 0, nil
	}, time.Minute)
	sampler.now = func() time.Time { return now }
	sampler.Step(context.Background())
	for _, status := range sampler.Current() {
		if status.OK || status.Failures != 1 {
			t.Fatalf("mismatched provider IP accepted: %+v", status)
		}
	}
	sampler.lookup = func(_ context.Context, p Provider, _ netip.Addr) (Result, time.Duration, error) {
		return Result{IP: ip}, 0, nil
	}
	now = now.Add(3 * time.Minute)
	sampler.Step(context.Background())
	now = now.Add(6 * time.Minute)
	for _, status := range sampler.Current() {
		if status.OK || !status.LastSuccess.IsZero() {
			t.Fatalf("stale result still visible: %+v", status)
		}
	}
}

func TestSamplerDiscardsInFlightChangedExitResult(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	sampler := NewSampler(func() (netip.Addr, bool) { return ip, true }, func(_ context.Context, p Provider, original netip.Addr) (Result, time.Duration, error) {
		ip = netip.MustParseAddr("9.9.9.9")
		return Result{IP: original, Latitude: 1, Longitude: 1, Country: "US"}, 0, nil
	}, time.Minute)
	sampler.Step(context.Background())
	for _, s := range sampler.Current() {
		if s.OK || !s.LastSuccess.IsZero() || s.ExitIP != ip {
			t.Fatalf("in-flight old exit leaked: %+v", s)
		}
	}
}
