package observability

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// LinkReader returns one fresh kernel link. Production executes inside the
// gateway pod netns; tests inject a reader and never inspect host links.
type LinkReader func(name string) (netlink.Link, error)

// GatewayLinkTraffic collects kernel link stats for a fixed device-role list.
// Link bytes/packets can reset on link recreation: these are gauges, NOT
// process-lifetime counters. No device names, peers or workload identities are
// emitted as label values.
type GatewayLinkTraffic struct {
	roles []linkRole
	read  LinkReader
	sem   chan struct{}
}
type linkRole struct{ label, name string }

// NewGatewayLinkTraffic rejects no dynamic labels: the caller can only select
// the predeclared optional WireGuard role, never provide a custom device name.
func NewGatewayLinkTraffic(encrypted bool, read LinkReader) *GatewayLinkTraffic {
	roles := []linkRole{{label: "geneve", name: datapath.GatewayDevice}, {label: "upstream", name: datapath.UpstreamDevice}}
	if encrypted {
		roles = append(roles, linkRole{label: "wireguard", name: datapath.WireGuardDevice})
	}
	return &GatewayLinkTraffic{roles: roles, read: read, sem: make(chan struct{}, 1)}
}

var (
	linkSampleOK  = prometheus.NewDesc("ratatoskr_gateway_link_sample_ok", "1 if this fixed gateway link's current kernel stats were sampled; 0 if unavailable or timed out.", []string{"role"}, nil)
	linkRXBytes   = prometheus.NewDesc("ratatoskr_gateway_link_receive_bytes", "Current kernel link receive bytes (resettable gauge).", []string{"role"}, nil)
	linkTXBytes   = prometheus.NewDesc("ratatoskr_gateway_link_transmit_bytes", "Current kernel link transmit bytes (resettable gauge).", []string{"role"}, nil)
	linkRXPackets = prometheus.NewDesc("ratatoskr_gateway_link_receive_packets", "Current kernel link receive packets (resettable gauge).", []string{"role"}, nil)
	linkTXPackets = prometheus.NewDesc("ratatoskr_gateway_link_transmit_packets", "Current kernel link transmit packets (resettable gauge).", []string{"role"}, nil)
)

func (c *GatewayLinkTraffic) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{linkSampleOK, linkRXBytes, linkTXBytes, linkRXPackets, linkTXPackets} {
		ch <- desc
	}
}

type linkResult struct{ samples []*netlink.LinkStatistics }

func (c *GatewayLinkTraffic) readAll() linkResult {
	result := linkResult{samples: make([]*netlink.LinkStatistics, len(c.roles))}
	if c.read == nil {
		return result
	}
	for i, role := range c.roles {
		link, err := c.read(role.name)
		if err != nil || link == nil || link.Attrs() == nil || link.Attrs().Name != role.name || link.Attrs().Statistics == nil {
			continue
		}
		stat := *link.Attrs().Statistics // copy before another reader can update injected test objects
		result.samples[i] = &stat
	}
	return result
}
func (c *GatewayLinkTraffic) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	select {
	case c.sem <- struct{}{}:
		// A netlink read has no cancellation. Exactly one worker is permitted;
		// keep the semaphore until it truly returns, even after scrape timeout.
		finished := make(chan linkResult, 1)
		go func() { result := c.readAll(); finished <- result; <-c.sem }()
		select {
		case result := <-finished:
			for i, role := range c.roles {
				stats := result.samples[i]
				if stats == nil || ctx.Err() != nil {
					ch <- prometheus.MustNewConstMetric(linkSampleOK, prometheus.GaugeValue, 0, role.label)
					continue
				}
				ch <- prometheus.MustNewConstMetric(linkSampleOK, prometheus.GaugeValue, 1, role.label)
				ch <- prometheus.MustNewConstMetric(linkRXBytes, prometheus.GaugeValue, float64(stats.RxBytes), role.label)
				ch <- prometheus.MustNewConstMetric(linkTXBytes, prometheus.GaugeValue, float64(stats.TxBytes), role.label)
				ch <- prometheus.MustNewConstMetric(linkRXPackets, prometheus.GaugeValue, float64(stats.RxPackets), role.label)
				ch <- prometheus.MustNewConstMetric(linkTXPackets, prometheus.GaugeValue, float64(stats.TxPackets), role.label)
			}
		case <-ctx.Done():
			for _, role := range c.roles {
				ch <- prometheus.MustNewConstMetric(linkSampleOK, prometheus.GaugeValue, 0, role.label)
			}
		}
	case <-ctx.Done():
		for _, role := range c.roles {
			ch <- prometheus.MustNewConstMetric(linkSampleOK, prometheus.GaugeValue, 0, role.label)
		}
	}
}

var _ prometheus.Collector = (*GatewayLinkTraffic)(nil)
