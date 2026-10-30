//go:build linux

// Package ebpf implements the CNI-independent datapath contract using a
// clsact tc egress selector and an external GENEVE device. Kernel BPF objects
// are loaded inside the caller's locked pod network namespace.
package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
)

const filterPriority uint16 = 420
const filterHandle uint32 = 0x52540001
const maxBPFEntries = 4096
const maxBPFExclusions = 1024

// Backend owns the selected client tc attachment. Gateway termination remains
// the validated iproute GENEVE/flower/kill-switch backend on the same netns.
type Backend struct {
	h       *netlink.Handle
	gateway *iproute.Backend
	objects *clientObjects
}

var _ datapath.Backend = (*Backend)(nil)

// New captures the calling thread's network namespace, like iproute.New.
// Callers must hold runtime.LockOSThread until programming completes. No bpffs
// mount is required: maps and program are fd-backed and held by tc attachment.
func New() (*Backend, error) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	return &Backend{h: h}, nil
}
func (b *Backend) Close() {
	if b.objects != nil {
		_ = b.objects.Close()
		b.objects = nil
	}
	if b.gateway != nil {
		b.gateway.Close()
		b.gateway = nil
	}
	if b.h != nil {
		b.h.Close()
		b.h = nil
	}
}
func (b *Backend) ApplyGateway(ctx context.Context, c datapath.GatewayConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Encryption == "wireguard" {
		return fmt.Errorf("ebpf gateway does not support WireGuard; refusing plaintext fallback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.gateway == nil {
		gw, err := iproute.New()
		if err != nil {
			return err
		}
		b.gateway = gw
	}
	return b.gateway.ApplyGateway(ctx, c)
}
func (b *Backend) ApplyClient(ctx context.Context, c datapath.ClientConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Encryption == "wireguard" {
		return fmt.Errorf("ebpf client does not support WireGuard; refusing plaintext fallback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	eth, err := b.h.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("client eth0: %w", err)
	}
	// Refuse any earlier clsact egress action (including terminal pass)
	// before creating tunnel/maps. Such a filter could bypass our drop.
	if err := b.checkEgressFilters(eth); err != nil {
		return err
	}
	// Revoke a previous healthy selector before any route, GENEVE or program
	// load can fail during an endpoint update. The old tc program continues
	// to enforce its exclusions and drops all previously steered traffic.
	if err := b.revokeOldEndpoint(eth); err != nil {
		return err
	}
	addrs, err := b.h.AddrList(eth, unix.AF_INET6)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if a.IP == nil {
			continue
		}
		if v, ok := netip.AddrFromSlice(a.IP); ok && v.Is6() && !v.IsLinkLocalUnicast() && !v.IsUnspecified() {
			return fmt.Errorf("ebpf IPv4-only mode refuses eth0 IPv6 address %s", v)
		}
	}
	// A restarted agent cannot silently leave an iproute catch-all active.
	existingRules, err := b.h.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}
	for _, r := range existingRules {
		if r.Protocol == datapath.RouteProtocol && r.Priority >= datapath.RulePriority && r.Priority <= datapath.RulePriority+999 {
			return fmt.Errorf("existing iproute steering rule at priority %d must be removed before ebpf apply", r.Priority)
		}
	}
	link, err := b.h.LinkByName(datapath.ClientDevice)
	if err != nil {
		var missing netlink.LinkNotFoundError
		if !errors.As(err, &missing) {
			return err
		}
	}
	if link != nil {
		return fmt.Errorf("existing iproute client device %s prevents ebpf apply", datapath.ClientDevice)
	}
	if c.Endpoint.IsValid() {
		// Kernel v5.10 ignores local_ipv4 in bpf_tunnel_key. Ensure the
		// actual underlay source selected by Geneve is this pod's IPv4.
		underlay, err := b.h.RouteGet(net.IP(c.Endpoint.AsSlice()))
		if err != nil {
			return fmt.Errorf("GENEVE endpoint lacks pod underlay route: %w", err)
		}
		if len(underlay) == 0 || !underlay[0].Src.Equal(net.IP(c.PodIP.AsSlice())) {
			return fmt.Errorf("GENEVE endpoint route must source client pod IP %s", c.PodIP)
		}
	}
	var geneve netlink.Link
	if c.Endpoint.IsValid() {
		geneve, err = b.ensureGeneve(c.MTU)
		if err != nil {
			return err
		}
	}
	next := &clientObjects{}
	if err := loadClientObjects(next, nil); err != nil {
		return fmt.Errorf("load ebpf tc program: %w", err)
	}
	if err := populate(next, c, geneve); err != nil {
		_ = next.Close()
		return err
	}
	if !c.Endpoint.IsValid() {
		// During an unhealthy transition, remove the previous encapsulation
		// path before replacing the old tc program. An old redirect can only
		// fail closed while the new no-endpoint selector is attached.
		old, err := b.h.FilterList(eth, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			_ = next.Close()
			return err
		}
		owned := false
		for _, f := range old {
			if bf, ok := f.(*netlink.BpfFilter); ok && f.Attrs().Priority == filterPriority && f.Attrs().Handle == filterHandle && bf.Name == "ratatoskr_ebpf" {
				owned = true
			}
		}
		if owned {
			if link, err := b.h.LinkByName(datapath.GatewayDevice); err == nil {
				if g, ok := link.(*netlink.Geneve); !ok || !g.FlowBased {
					_ = next.Close()
					return fmt.Errorf("gnv0 is not external GENEVE")
				}
				if err := b.h.LinkDel(link); err != nil {
					_ = next.Close()
					return err
				}
			}
		}
	}
	if err := b.attach(eth, next); err != nil {
		_ = next.Close()
		return err
	}
	previous := b.objects
	b.objects = next
	if previous != nil {
		_ = previous.Close()
	}
	return ctx.Err()
}
func (b *Backend) ensureGeneve(mtu int) (netlink.Link, error) {
	link, err := b.h.LinkByName(datapath.GatewayDevice)
	if err != nil {
		var missing netlink.LinkNotFoundError
		if !errors.As(err, &missing) {
			return nil, err
		}
	}
	if link == nil {
		mac, _ := net.ParseMAC(datapath.ClientMAC)
		g := &netlink.Geneve{LinkAttrs: netlink.LinkAttrs{Name: datapath.GatewayDevice, MTU: mtu, HardwareAddr: mac}, FlowBased: true, Dport: datapath.GenevePort, UdpCsum: 1}
		if err := b.h.LinkAdd(g); err != nil {
			return nil, fmt.Errorf("create external GENEVE: %w", err)
		}
		link, err = b.h.LinkByName(datapath.GatewayDevice)
		if err != nil {
			return nil, err
		}
	}
	g, ok := link.(*netlink.Geneve)
	if !ok || !g.FlowBased {
		return nil, fmt.Errorf("gnv0 must be collect_md GENEVE")
	}
	if err := b.h.LinkSetMTU(link, mtu); err != nil {
		return nil, err
	}
	// Kernel loose reverse-path validation treats an unnumbered GENEVE
	// interface as lacking a valid source path. The owned /32 is distinct
	// from the gateway neighbor .1 and creates only a local-table route.
	if err := b.ensureGeneveAddress(link); err != nil {
		return nil, err
	}
	if err := b.h.LinkSetUp(link); err != nil {
		return nil, err
	}
	return link, nil
}
func (b *Backend) checkEgressFilters(eth netlink.Link) error {
	filters, err := b.h.FilterList(eth, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return err
	}
	for _, f := range filters {
		if f.Attrs().Priority > filterPriority {
			continue
		}
		bf, ok := f.(*netlink.BpfFilter)
		if f.Attrs().Priority != filterPriority || !ok || f.Attrs().Handle != filterHandle || bf.Name != "ratatoskr_ebpf" || !bf.DirectAction || f.Attrs().Protocol != unix.ETH_P_ALL {
			return fmt.Errorf("tc egress filter at priority %d could bypass Ratatoskr selector", f.Attrs().Priority)
		}
	}
	return nil
}
func (b *Backend) attach(eth netlink.Link, objects *clientObjects) error {
	q := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: eth.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}}
	if err := b.h.QdiscAdd(q); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	// Recheck immediately before FilterReplace, including on agent updates.
	if err := b.checkEgressFilters(eth); err != nil {
		return err
	}
	filter := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: eth.Attrs().Index, Parent: netlink.HANDLE_MIN_EGRESS, Priority: filterPriority, Handle: filterHandle, Protocol: unix.ETH_P_ALL}, Fd: objects.Steer.FD(), Name: "ratatoskr_ebpf", DirectAction: true}
	if err := b.h.FilterReplace(filter); err != nil {
		return fmt.Errorf("attach tc egress: %w", err)
	}
	return nil
}
func (b *Backend) RemoveClient(ctx context.Context, c datapath.ClientConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	eth, err := b.h.LinkByName("eth0")
	if err == nil {
		filters, err := b.h.FilterList(eth, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			return err
		}
		for _, f := range filters {
			if f.Attrs().Priority == filterPriority && f.Attrs().Handle == filterHandle {
				if bf, ok := f.(*netlink.BpfFilter); ok && strings.HasPrefix(bf.Name, "ratatoskr_ebpf") {
					if err := b.h.FilterDel(f); err != nil {
						return err
					}
				}
			}
		}
	} else {
		var missing netlink.LinkNotFoundError
		if !errors.As(err, &missing) {
			return err
		}
	}
	if link, err := b.h.LinkByName(datapath.GatewayDevice); err == nil {
		g, ok := link.(*netlink.Geneve)
		if !ok || !g.FlowBased {
			return fmt.Errorf("gnv0 is not external GENEVE")
		}
		if err := b.h.LinkDel(link); err != nil {
			return err
		}
	} else {
		var missing netlink.LinkNotFoundError
		if !errors.As(err, &missing) {
			return err
		}
	}
	if b.objects != nil {
		_ = b.objects.Close()
		b.objects = nil
	}
	return ctx.Err()
}
func addrU32(ip netip.Addr) uint32 { return binary.NativeEndian.Uint32(ip.AsSlice()) }
func prefixKey(prefix netip.Prefix) clientLpmV4 {
	return clientLpmV4{Prefixlen: uint32(prefix.Bits()), Addr: addrU32(prefix.Masked().Addr())} // #nosec G115 -- validated IPv4 bits are 0..32.
}
func ruleKey(index uint32, prefix netip.Prefix) clientLpmRule {
	return clientLpmRule{Prefixlen: uint32(32 + prefix.Bits()), Rule: index, Addr: addrU32(prefix.Masked().Addr())} // #nosec G115 -- validated IPv4 bits give 32..64.
}
func identityTLV(c datapath.ClientConfig) clientGeneveOpt {
	h := fnv.New64a()
	_, _ = h.Write([]byte(c.Identity.Namespace))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(c.Identity.UID))
	var out clientGeneveOpt
	// GENEVE option class 0x5254, type 1, two 4-byte words of identity hash.
	out.Cls = binary.NativeEndian.Uint16([]byte{0x52, 0x54})
	out.Type = 1
	out.Len = 2
	binary.BigEndian.PutUint64(out.Identity[:], h.Sum64())
	return out
}
