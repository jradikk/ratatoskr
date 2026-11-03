package observability

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ConnectionScope is a successfully applied, ready client set and the current
// upstream interface's IPv4 SNAT addresses. An unavailable scope is unknown,
// not a known zero. The caller must not expose an optimistic desired client set.
type ConnectionScope func() (clients []netip.Addr, upstream []netip.Addr, err error)
type ConntrackReader func() ([]*netlink.ConntrackFlow, error)

// GatewayConnections samples only IPv4 TCP/UDP conntrack tuples whose original
// source is a selected client and whose reply destination is the upstream SNAT
// address. It counts tracked NAT flows (not live sockets or healthy VPN peers).
// Conntrack does not record ingress interface, so the tuple match is the limit
// of what this kernel source can prove. There are no client-IP metric labels.
type GatewayConnections struct {
	scope ConnectionScope
	read  ConntrackReader
	sem   chan struct{}
}

func NewGatewayConnections(scope ConnectionScope, read ConntrackReader) *GatewayConnections {
	return &GatewayConnections{scope: scope, read: read, sem: make(chan struct{}, 1)}
}

var (
	connectionsSampleOK  = prometheus.NewDesc("ratatoskr_gateway_connections_sample_ok", "1 when selected-client, upstream SNAT and IPv4 conntrack sampling all succeeded; 0 means unknown.", nil, nil)
	forwardedConnections = prometheus.NewDesc("ratatoskr_gateway_forwarded_connections", "Current IPv4 selected-client SNAT conntrack entries (resettable gauge, not established sockets).", []string{"protocol"}, nil)
)

func (c *GatewayConnections) Describe(ch chan<- *prometheus.Desc) {
	ch <- connectionsSampleOK
	ch <- forwardedConnections
}
func (c *GatewayConnections) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	select {
	case c.sem <- struct{}{}:
		finished := make(chan connectionResult, 1)
		go func() { finished <- c.sample(); <-c.sem }()
		select {
		case result := <-finished:
			if ctx.Err() != nil || result.err != nil {
				ch <- prometheus.MustNewConstMetric(connectionsSampleOK, prometheus.GaugeValue, 0)
				return
			}
			ch <- prometheus.MustNewConstMetric(connectionsSampleOK, prometheus.GaugeValue, 1)
			ch <- prometheus.MustNewConstMetric(forwardedConnections, prometheus.GaugeValue, float64(result.tcp), "TCP")
			ch <- prometheus.MustNewConstMetric(forwardedConnections, prometheus.GaugeValue, float64(result.udp), "UDP")
		case <-ctx.Done():
			ch <- prometheus.MustNewConstMetric(connectionsSampleOK, prometheus.GaugeValue, 0)
		}
	case <-ctx.Done():
		ch <- prometheus.MustNewConstMetric(connectionsSampleOK, prometheus.GaugeValue, 0)
	}
}

type connectionResult struct {
	tcp, udp int
	err      error
}

func (c *GatewayConnections) sample() connectionResult {
	if c.scope == nil || c.read == nil {
		return connectionResult{err: errors.New("conntrack sampler unavailable")}
	}
	clients, upstream, err := c.scope()
	if err != nil || len(upstream) == 0 {
		return connectionResult{err: errors.New("upstream or selected-client scope unavailable")}
	}
	origins := make(map[netip.Addr]struct{}, len(clients))
	for _, ip := range clients {
		if !ip.Is4() || ip.IsUnspecified() {
			return connectionResult{err: errors.New("invalid selected-client IPv4 scope")}
		}
		origins[ip] = struct{}{}
	}
	destinations := make(map[netip.Addr]struct{}, len(upstream))
	for _, ip := range upstream {
		if !ip.Is4() || ip.IsUnspecified() {
			return connectionResult{err: errors.New("invalid upstream IPv4 scope")}
		}
		destinations[ip] = struct{}{}
	}
	flows, err := c.read()
	if err != nil {
		return connectionResult{err: err}
	}
	var result connectionResult
	for _, flow := range flows {
		if flow == nil || flow.FamilyType != unix.AF_INET || flow.Zone != 0 {
			continue
		}
		protocol := flow.Forward.Protocol
		if protocol != unix.IPPROTO_TCP && protocol != unix.IPPROTO_UDP || flow.Reverse.Protocol != protocol {
			continue
		}
		src, ok1 := netip.AddrFromSlice(flow.Forward.SrcIP)
		dst, ok2 := netip.AddrFromSlice(flow.Forward.DstIP)
		replySrc, ok3 := netip.AddrFromSlice(flow.Reverse.SrcIP)
		replyDst, ok4 := netip.AddrFromSlice(flow.Reverse.DstIP)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			continue
		}
		if _, ok := origins[src.Unmap()]; !ok || dst.Unmap() != replySrc.Unmap() {
			continue
		}
		if _, ok := destinations[replyDst.Unmap()]; !ok || replyDst.Unmap() == src.Unmap() {
			continue
		}
		if flow.Forward.DstPort != flow.Reverse.SrcPort {
			continue
		}
		if protocol == unix.IPPROTO_TCP {
			result.tcp++
		} else {
			result.udp++
		}
	}
	return result
}

// KernelConnectionScope resolves IPv4 addresses assigned to the owned
// upstream0 device. An empty address set is unknown, never a healthy zero.
func KernelConnectionScope(clients []netip.Addr) ([]netip.Addr, []netip.Addr, error) {
	link, err := netlink.LinkByName(datapath.UpstreamDevice)
	if err != nil {
		return nil, nil, err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, nil, err
	}
	upstream := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(addr.IP.To4())
		if ok && ip.Is4() && !ip.IsUnspecified() {
			upstream = append(upstream, ip)
		}
	}
	return clients, upstream, nil
}

// KernelConntrackFlows obtains one complete IPv4 table dump. Interrupted or
// failed dumps are errors, never partial zero-valued samples.
func KernelConntrackFlows() ([]*netlink.ConntrackFlow, error) {
	return netlink.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
}

var _ prometheus.Collector = (*GatewayConnections)(nil)
