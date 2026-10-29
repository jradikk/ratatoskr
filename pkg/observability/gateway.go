// Package observability provides bounded, public-safe gateway metrics.
package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// GatewayHandler exposes one zero-label gauge derived on every scrape from the
// gateway's effective readiness (upstream probe AND datapath applied). It uses
// a private registry: process/runtime and per-client/peer labels are omitted.
// Peers are intentionally not counted: registered peers are not a trustworthy
// healthy-peer count without consulting authenticated live kernel state.
func GatewayHandler(healthy func() bool) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "ratatoskr_gateway_upstream_healthy",
		Help: "1 when the gateway has a healthy upstream and applied ready datapath, otherwise 0.",
	}, func() float64 {
		if healthy() {
			return 1
		}
		return 0
	}))
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}
