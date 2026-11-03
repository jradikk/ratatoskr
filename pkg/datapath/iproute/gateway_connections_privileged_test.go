//go:build linux && privileged

package iproute

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/skaldhall/ratatoskr/pkg/observability"
)

// Samples real, bidirectionally forwarded GENEVE->upstream0 SNAT flows in a
// disposable three-netns gateway fixture; never accesses host conntrack.
func TestPrivilegedGatewayForwardedConnectionsRealSNAT(t *testing.T) {
	gatewayBidirectionalReturnWithHook(t, 1500, 1400, 0, func(gatewayNS netns.NsHandle, client netip.Addr, actualSNAT net.IP) {
		upstream := netip.MustParseAddr("198.19.0.2")
		if !actualSNAT.Equal(net.ParseIP(upstream.String())) {
			t.Fatalf("actual upstream UDP source=%s, want gateway SNAT=%s", actualSNAT, upstream)
		}
		inGateway := func(f func() error) error {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			previous, e := netns.Get()
			if e != nil {
				return e
			}
			defer previous.Close()
			if e = netns.Set(gatewayNS); e != nil {
				return e
			}
			defer func() {
				if restore := netns.Set(previous); restore != nil {
					t.Errorf("restore reader namespace: %v", restore)
				}
			}()
			return f()
		}
		selected := client
		collector := func() *observability.GatewayConnections {
			return observability.NewGatewayConnections(func() ([]netip.Addr, []netip.Addr, error) {
				var clients, upstream []netip.Addr
				e := inGateway(func() error {
					var err error
					clients, upstream, err = observability.KernelConnectionScope([]netip.Addr{selected})
					return err
				})
				return clients, upstream, e
			}, func() ([]*netlink.ConntrackFlow, error) {
				var flows []*netlink.ConntrackFlow
				e := inGateway(func() error { var err error; flows, err = observability.KernelConntrackFlows(); return err })
				return flows, e
			})
		}
		scrape := func() string {
			t.Helper()
			reg := prometheus.NewRegistry()
			reg.MustRegister(collector())
			rec := httptest.NewRecorder()
			promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("scrape status=%d: %s", rec.Code, rec.Body.String())
			}
			return rec.Body.String()
		}
		check := func(text, want string) {
			t.Helper()
			if !strings.Contains(text, want+"\n") {
				t.Fatalf("missing %q in real conntrack scrape: %s", want, text)
			}
		}
		text := scrape()
		check(text, "ratatoskr_gateway_connections_sample_ok 1")
		check(text, "ratatoskr_gateway_forwarded_connections{protocol=\"TCP\"} 1")
		check(text, "ratatoskr_gateway_forwarded_connections{protocol=\"UDP\"} 1")
		selected = netip.MustParseAddr("10.42.3.9") // not a selected forwarding client
		text = scrape()
		check(text, "ratatoskr_gateway_connections_sample_ok 1")
		check(text, "ratatoskr_gateway_forwarded_connections{protocol=\"TCP\"} 0")
		check(text, "ratatoskr_gateway_forwarded_connections{protocol=\"UDP\"} 0")
	})
}
