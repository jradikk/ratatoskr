package observability

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func connFlow(src, dst, replyDst string, protocol uint8) *netlink.ConntrackFlow {
	return &netlink.ConntrackFlow{FamilyType: unix.AF_INET,
		Forward: netlink.IPTuple{SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst), SrcPort: 54321, DstPort: 443, Protocol: protocol},
		Reverse: netlink.IPTuple{SrcIP: net.ParseIP(dst), DstIP: net.ParseIP(replyDst), SrcPort: 443, DstPort: 54321, Protocol: protocol}}
}
func connectionText(t *testing.T, collector *GatewayConnections) string {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}
func TestGatewayConnectionsOnlySelectedSNATFlows(t *testing.T) {
	selected := netip.MustParseAddr("10.42.0.7")
	upstream := netip.MustParseAddr("10.64.0.2")
	scope := func() ([]netip.Addr, []netip.Addr, error) { return []netip.Addr{selected}, []netip.Addr{upstream}, nil }
	goodTCP := connFlow(selected.String(), "8.8.8.8", upstream.String(), unix.IPPROTO_TCP)
	goodUDP := connFlow(selected.String(), "1.1.1.1", upstream.String(), unix.IPPROTO_UDP)
	wrongSNAT := connFlow(selected.String(), "1.1.1.1", "10.64.0.99", unix.IPPROTO_TCP)
	otherClient := connFlow("10.42.0.8", "8.8.8.8", upstream.String(), unix.IPPROTO_TCP)
	localSocket := connFlow(upstream.String(), "8.8.8.8", upstream.String(), unix.IPPROTO_TCP)
	noNAT := connFlow(selected.String(), "8.8.8.8", selected.String(), unix.IPPROTO_TCP)
	wrongZone := connFlow(selected.String(), "8.8.8.8", upstream.String(), unix.IPPROTO_TCP)
	wrongZone.Zone = 2
	malformed := connFlow(selected.String(), "8.8.8.8", upstream.String(), unix.IPPROTO_TCP)
	malformed.Reverse.SrcIP = net.ParseIP("7.7.7.7")
	text := connectionText(t, NewGatewayConnections(scope, func() ([]*netlink.ConntrackFlow, error) {
		return []*netlink.ConntrackFlow{goodTCP, goodUDP, wrongSNAT, otherClient, localSocket, noNAT, wrongZone, malformed, nil}, nil
	}))
	for _, line := range []string{"ratatoskr_gateway_connections_sample_ok 1\n", "ratatoskr_gateway_forwarded_connections{protocol=\"TCP\"} 1\n", "ratatoskr_gateway_forwarded_connections{protocol=\"UDP\"} 1\n"} {
		if !strings.Contains(text, line) {
			t.Fatalf("missing %q: %s", line, text)
		}
	}
}
func TestGatewayConnectionsKnownZeroAndUnknown(t *testing.T) {
	selected := netip.MustParseAddr("10.42.0.7")
	upstream := netip.MustParseAddr("10.64.0.2")
	for _, tc := range []struct {
		name  string
		scope ConnectionScope
		read  ConntrackReader
		known bool
	}{
		{"empty table", func() ([]netip.Addr, []netip.Addr, error) { return []netip.Addr{selected}, []netip.Addr{upstream}, nil }, func() ([]*netlink.ConntrackFlow, error) { return nil, nil }, true},
		{"no selected clients", func() ([]netip.Addr, []netip.Addr, error) { return nil, []netip.Addr{upstream}, nil }, func() ([]*netlink.ConntrackFlow, error) { return nil, nil }, true},
		{"unknown upstream", func() ([]netip.Addr, []netip.Addr, error) { return []netip.Addr{selected}, nil, nil }, func() ([]*netlink.ConntrackFlow, error) { return nil, nil }, false},
		{"scope failure", func() ([]netip.Addr, []netip.Addr, error) { return nil, nil, errors.New("not ready") }, func() ([]*netlink.ConntrackFlow, error) { return nil, nil }, false},
		{"partial dump", func() ([]netip.Addr, []netip.Addr, error) { return []netip.Addr{selected}, []netip.Addr{upstream}, nil }, func() ([]*netlink.ConntrackFlow, error) {
			return []*netlink.ConntrackFlow{connFlow(selected.String(), "8.8.8.8", upstream.String(), unix.IPPROTO_TCP)}, errors.New("dump interrupted")
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := connectionText(t, NewGatewayConnections(tc.scope, tc.read))
			if !strings.Contains(text, "ratatoskr_gateway_connections_sample_ok "+map[bool]string{true: "1", false: "0"}[tc.known]+"\n") {
				t.Fatal(text)
			}
			if strings.Contains(text, "ratatoskr_gateway_forwarded_connections{protocol=\"TCP\"} ") != tc.known {
				t.Fatal(text)
			}
		})
	}
}
func TestGatewayConnectionsTimedOutReadIsBoundedUnknown(t *testing.T) {
	start := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	collector := NewGatewayConnections(func() ([]netip.Addr, []netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.42.0.7")}, []netip.Addr{netip.MustParseAddr("10.64.0.2")}, nil
	}, func() ([]*netlink.ConntrackFlow, error) { calls.Add(1); close(start); <-release; return nil, nil })
	first := make(chan string, 1)
	go func() { first <- connectionText(t, collector) }()
	select {
	case <-start:
	case <-time.After(time.Second):
		t.Fatal("reader did not start")
	}
	select {
	case text := <-first:
		if !strings.Contains(text, "ratatoskr_gateway_connections_sample_ok 0\n") {
			t.Fatal(text)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("read not bounded")
	}
	text := connectionText(t, collector)
	if calls.Load() != 1 || !strings.Contains(text, "ratatoskr_gateway_connections_sample_ok 0\n") {
		t.Fatal("stacked kernel reads or reported known")
	}
	close(release)
}
