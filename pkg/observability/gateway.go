// Package observability provides bounded, public-safe gateway metrics.
package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// GatewayHandler exposes zero-label gauges derived on every scrape from the
// gateway's published state (upstream probe AND datapath applied). A non-ready
// or unknown effective MTU is reported as zero. It uses a private registry:
// process/runtime and per-client/peer labels are omitted. Link metrics use only
// fixed device-role labels; they are current resettable kernel samples, not
// per-client counters or a claim about healthy WireGuard peers.
func GatewayHandler(snapshot func() (ready bool, effectiveMTU int), programming *GatewayProgramming, traffic *GatewayLinkTraffic, connections ...*GatewayConnections) http.Handler {
	registry := prometheus.NewRegistry()
	registerGatewayMetrics(registry, snapshot)
	programming.register(registry)
	registry.MustRegister(traffic)
	if len(connections) != 0 && connections[0] != nil {
		registry.MustRegister(connections[0])
	}
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

func registerGatewayMetrics(registry *prometheus.Registry, snapshot func() (bool, int)) {
	registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "ratatoskr_gateway_upstream_healthy",
		Help: "1 when the gateway has a healthy upstream and applied ready datapath, otherwise 0.",
	}, func() float64 {
		ready, _ := snapshot()
		if ready {
			return 1
		}
		return 0
	}))
	registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "ratatoskr_gateway_effective_mtu_bytes",
		Help: "Measured effective gateway inner MTU in bytes when ready, otherwise 0.",
	}, func() float64 {
		ready, effectiveMTU := snapshot()
		if !ready || effectiveMTU <= 0 {
			return 0
		}
		return float64(effectiveMTU)
	}))
}
