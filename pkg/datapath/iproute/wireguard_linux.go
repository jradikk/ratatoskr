//go:build linux

package iproute

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/wireguard"
)

var _ datapath.WireGuardManager = (*Backend)(nil)

const wgBypassPriority = 8990
const wgRoutePriority = 8991

func (b *Backend) wireguardRule(priority, table int, mark uint32, dst netip.Addr) error {
	r := netlink.NewRule()
	r.Priority = priority
	r.Table = table
	if mark != 0 {
		r.Mark = mark
		mask := datapath.MarkMask
		r.Mask = &mask
	}
	if dst.IsValid() {
		r.Dst = host(dst)
	}
	return b.rule(r)
}
func (b *Backend) wireguardRoutes(local, remote netip.Addr, peerReady bool) error {
	fr := fallback(datapath.WireGuardTable)
	if err := b.h.RouteReplace(&fr); err != nil {
		return err
	}
	// WireGuard sockets and explicitly marked registration sockets use MAIN.
	if err := b.wireguardRule(wgBypassPriority, unix.RT_TABLE_MAIN, datapath.WireGuardMark, netip.Addr{}); err != nil {
		return err
	}
	// Withdraw stale healthy routes before changing the peer endpoint.
	routes, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: datapath.WireGuardTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Type == unix.RTN_UNICAST && int(r.Protocol) == datapath.RouteProtocol {
			if err := b.h.RouteDel(&r); err != nil {
				return err
			}
		}
	}
	rules, err := b.h.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.Priority == wgRoutePriority && r.Protocol == datapath.RouteProtocol {
			if err := b.h.RuleDel(&r); err != nil {
				return err
			}
		}
	}
	if !peerReady {
		return nil
	}
	if !remote.Is4() || remote.IsUnspecified() {
		return fmt.Errorf("WireGuard gateway must have valid IPv4 endpoint")
	}
	if err := b.wireguardRule(wgRoutePriority, datapath.WireGuardTable, 0, remote); err != nil {
		return err
	}
	link, err := b.h.LinkByName(datapath.WireGuardDevice)
	if err != nil {
		return err
	}
	r := netlink.Route{Family: unix.AF_INET, Dst: host(remote), Table: datapath.WireGuardTable, LinkIndex: link.Attrs().Index, Src: ip(local), Scope: netlink.SCOPE_LINK, Protocol: datapath.RouteProtocol}
	return b.h.RouteReplace(&r)
}
func (b *Backend) removeWireGuardRoutes() error {
	rules, err := b.h.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if (r.Priority == wgBypassPriority || r.Priority == wgRoutePriority) && r.Protocol == datapath.RouteProtocol {
			if err := b.h.RuleDel(&r); err != nil {
				return err
			}
		}
	}
	routes, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: datapath.WireGuardTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if int(r.Protocol) == datapath.RouteProtocol {
			if err := b.h.RouteDel(&r); err != nil {
				return err
			}
		}
	}
	return nil
}

// PrepareClientWireGuard creates/retains the client kernel identity before
// authenticated HTTPS registration. It installs NO peer or WG route: the
// registration socket must be explicitly marked WireGuardMark by the caller.
func (b *Backend) PrepareClientWireGuard(ctx context.Context, c datapath.ClientConfig) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if c.Encryption != "wireguard" {
		return "", fmt.Errorf("WireGuard preparation requires wireguard encryption")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := b.rejectDualStack(); err != nil {
		return "", err
	}
	return wireguard.Ensure(b.h, datapath.WireGuardDevice, c.WireGuardPort, datapath.WireGuardMark)
}

// WireGuardPublicKey publishes only the public key of the current gateway (or
// pre-registered client) kernel identity, never the private key.
func (b *Backend) WireGuardPublicKey() (string, error) {
	return wireguard.PublicKey(datapath.WireGuardDevice)
}

// gatewayRoute adds one authenticated client without changing other peers.
func (b *Backend) gatewayRoute(gatewayIP, clientIP netip.Addr) error {
	fr := fallback(datapath.WireGuardTable)
	if err := b.h.RouteReplace(&fr); err != nil {
		return err
	}
	if err := b.wireguardRule(wgBypassPriority, unix.RT_TABLE_MAIN, datapath.WireGuardMark, netip.Addr{}); err != nil {
		return err
	}
	all, err := b.h.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}
	owned := false
	for _, r := range all {
		if r.Priority == wgRoutePriority && r.Dst != nil && r.Dst.String() == host(clientIP).String() {
			if r.Table != datapath.WireGuardTable || r.Protocol != datapath.RouteProtocol {
				return fmt.Errorf("WireGuard client route priority occupied")
			}
			owned = true
		}
	}
	if !owned {
		r := netlink.NewRule()
		r.Priority = wgRoutePriority
		r.Table = datapath.WireGuardTable
		r.Dst = host(clientIP)
		r.Family = unix.AF_INET
		r.Protocol = datapath.RouteProtocol
		r.Type = unix.RTN_UNICAST
		if err := b.h.RuleAdd(r); err != nil {
			return err
		}
	}
	link, err := b.h.LinkByName(datapath.WireGuardDevice)
	if err != nil {
		return err
	}
	r := netlink.Route{Family: unix.AF_INET, Dst: host(clientIP), Table: datapath.WireGuardTable, LinkIndex: link.Attrs().Index, Src: ip(gatewayIP), Scope: netlink.SCOPE_LINK, Protocol: datapath.RouteProtocol}
	return b.h.RouteReplace(&r)
}

// RegisterPeer must be called ONLY after gateway TokenReview and current Pod
// identity checks. No peer is created from GatewayConfig.Clients alone.
func (b *Backend) RegisterPeer(ctx context.Context, gatewayIP, clientIP netip.Addr, clientPublicKey string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !gatewayIP.Is4() || !clientIP.Is4() || gatewayIP == clientIP || clientIP.IsUnspecified() {
		return fmt.Errorf("invalid WireGuard gateway/client PodIP")
	}
	if err := wireguard.GatewayPeer(datapath.WireGuardDevice, clientIP, clientPublicKey); err != nil {
		return err
	}
	if err := b.gatewayRoute(gatewayIP, clientIP); err != nil {
		_ = wireguard.RemoveGatewayPeer(datapath.WireGuardDevice, clientIP)
		return err
	}
	return ctx.Err()
}
func (b *Backend) UnregisterPeer(ctx context.Context, clientIP netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Withdraw route before deleting peer; failure cannot leave a plaintext leg.
	routes, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: datapath.WireGuardTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Dst != nil && r.Dst.String() == host(clientIP).String() && r.Type == unix.RTN_UNICAST && int(r.Protocol) == datapath.RouteProtocol {
			if err := b.h.RouteDel(&r); err != nil {
				return err
			}
		}
	}
	all, err := b.h.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}
	for _, r := range all {
		if r.Priority == wgRoutePriority && r.Protocol == datapath.RouteProtocol && r.Dst != nil && r.Dst.String() == host(clientIP).String() {
			if err := b.h.RuleDel(&r); err != nil {
				return err
			}
		}
	}
	if err := wireguard.RemoveGatewayPeer(datapath.WireGuardDevice, clientIP); err != nil {
		return err
	}
	return ctx.Err()
}

// ClearGatewayPeers invalidates every peer retained by a prior gateway
// process in the same pod network namespace. The gateway's private kernel key,
// transport bypass rule and unreachable fallback remain intact; only freshly
// authenticated registration may subsequently restore a client route/peer.
func (b *Backend) ClearGatewayPeers(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	link, err := b.h.LinkByName(datapath.WireGuardDevice)
	if err != nil && !isMissing(err) {
		return err
	}
	if isMissing(err) {
		link = nil
	}
	// Revoke cryptographic ingress first. If a later netlink deletion fails,
	// stale routes lead to a device without authorized peers, not to an old key.
	if err == nil {
		if link.Type() != "wireguard" {
			return fmt.Errorf("%s is not a WireGuard link", datapath.WireGuardDevice)
		}
		if err := wireguard.ClearPeers(datapath.WireGuardDevice); err != nil {
			return fmt.Errorf("revoke gateway WireGuard peers: %w", err)
		}
	}
	routes, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: datapath.WireGuardTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Dst != nil && r.Type == unix.RTN_UNICAST && int(r.Protocol) == datapath.RouteProtocol && link != nil && r.LinkIndex == link.Attrs().Index {
			if err := b.h.RouteDel(&r); err != nil {
				return err
			}
		}
	}
	rules, err := b.h.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.Priority == wgRoutePriority && r.Protocol == datapath.RouteProtocol && r.Table == datapath.WireGuardTable && r.Dst != nil && r.Mark == 0 && r.IifName == "" && r.OifName == "" {
			if err := b.h.RuleDel(&r); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func (b *Backend) wireguardGatewayBase() error {
	fr := fallback(datapath.WireGuardTable)
	if err := b.h.RouteReplace(&fr); err != nil {
		return err
	}
	return b.wireguardRule(wgBypassPriority, unix.RT_TABLE_MAIN, datapath.WireGuardMark, netip.Addr{})
}
