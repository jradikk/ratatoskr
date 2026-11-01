package observability

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/skaldhall/ratatoskr/pkg/wireguard"
)

// WireGuardHandler extends a gateway's private metrics with kernel-only peer
// aggregates. Unknown samples are distinguishable from known zero; no labels,
// peer keys, IPs, bearer tokens, or profile fields are exported.
// A semaphore limits simultaneous wgctrl reads to one per gateway process.
func WireGuardHandler(readySnapshot func() (bool, int), programming *GatewayProgramming, traffic *GatewayLinkTraffic, deviceName string, read wireguard.DeviceReader) http.Handler {
	registry := prometheus.NewRegistry()
	registerGatewayMetrics(registry, readySnapshot)
	programming.register(registry)
	registry.MustRegister(traffic)
	sem := make(chan struct{}, 1)
	// Gather runs each GaugeFunc separately; take at most one fresh kernel read
	// per scrape via a single custom collector below.
	registry.MustRegister(&peerCollector{name: deviceName, read: read, sem: sem})
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

type peerCollector struct {
	name string
	read wireguard.DeviceReader
	sem  chan struct{}
}

var (
	peerSampleOK   = prometheus.NewDesc("ratatoskr_gateway_wireguard_sample_ok", "1 if current kernel peer sampling succeeded; 0 means unavailable or timed out.", nil, nil)
	peerInstalled  = prometheus.NewDesc("ratatoskr_gateway_wireguard_installed_peers", "Installed WireGuard peers reported by the kernel; not a healthy-peer count.", nil, nil)
	peerHandshaken = prometheus.NewDesc("ratatoskr_gateway_wireguard_handshaken_peers", "Installed peers with a nonzero last handshake, not necessarily healthy now.", nil, nil)
	peerAge        = prometheus.NewDesc("ratatoskr_gateway_wireguard_latest_handshake_age_seconds", "Age of most recent handshake; -1 means no peer has handshaken.", nil, nil)
	peerRX         = prometheus.NewDesc("ratatoskr_gateway_wireguard_receive_bytes", "Current aggregate kernel peer receive bytes, a resettable gauge.", nil, nil)
	peerTX         = prometheus.NewDesc("ratatoskr_gateway_wireguard_transmit_bytes", "Current aggregate kernel peer transmit bytes, a resettable gauge.", nil, nil)
)

func (c *peerCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{peerSampleOK, peerInstalled, peerHandshaken, peerAge, peerRX, peerTX} {
		ch <- d
	}
}
func (c *peerCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	select {
	case c.sem <- struct{}{}:
		// wgctrl Device has no cancellation. Keep the semaphore occupied until
		// the actual read finishes, even when this scrape times out; later scrapes
		// report unknown rather than spawning unbounded blocked readers.
		finished := make(chan struct{})
		reader := func(name string) (*wgtypes.Device, error) {
			defer close(finished)
			return c.read(name)
		}
		defer func() { go func() { <-finished; <-c.sem }() }()
		sample, err := wireguard.SampleDevice(ctx, c.name, time.Now(), reader)
		if ctx.Err() != nil {
			ch <- prometheus.MustNewConstMetric(peerSampleOK, prometheus.GaugeValue, 0)
			return
		}
		if err == nil {
			ch <- prometheus.MustNewConstMetric(peerSampleOK, prometheus.GaugeValue, 1)
			ch <- prometheus.MustNewConstMetric(peerInstalled, prometheus.GaugeValue, float64(sample.InstalledPeers))
			ch <- prometheus.MustNewConstMetric(peerHandshaken, prometheus.GaugeValue, float64(sample.HandshakenPeers))
			ch <- prometheus.MustNewConstMetric(peerAge, prometheus.GaugeValue, sample.LatestHandshakeAgeSeconds)
			ch <- prometheus.MustNewConstMetric(peerRX, prometheus.GaugeValue, float64(sample.ReceiveBytes))
			ch <- prometheus.MustNewConstMetric(peerTX, prometheus.GaugeValue, float64(sample.TransmitBytes))
		} else {
			ch <- prometheus.MustNewConstMetric(peerSampleOK, prometheus.GaugeValue, 0)
		}
	case <-ctx.Done():
		ch <- prometheus.MustNewConstMetric(peerSampleOK, prometheus.GaugeValue, 0)
	}
}

var _ prometheus.Collector = (*peerCollector)(nil)
