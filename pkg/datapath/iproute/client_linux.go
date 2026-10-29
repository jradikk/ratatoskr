//go:build linux

// Package iproute implements GENEVE steering using netlink and nftables.
package iproute

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

const fallbackMetric = 4294967295
const steeringMark uint32 = 0x00200000
const metadataPriority = datapath.RulePriority - 1

var metadataIP = netip.MustParsePrefix("169.254.169.254/32")

type Backend struct{ h *netlink.Handle }

var _ datapath.Backend = (*Backend)(nil)

// New captures the current network namespace. Callers entering another namespace
// must hold runtime.LockOSThread until all programming (including sysctls) ends.
func New() (*Backend, error) {
	// The driver has already entered the target namespace. Do not setns even
	// to our current namespace: that would need SYS_ADMIN in the init driver,
	// whose contract grants NET_ADMIN only.
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	return &Backend{h: h}, nil
}
func (b *Backend) Close()              { b.h.Close() }
func (b *Backend) nft() *nftables.Conn { return &nftables.Conn{} }
func ip(a netip.Addr) net.IP           { v := a.As4(); return net.IP(v[:]) }
func prefix(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: ip(p.Masked().Addr()), Mask: net.CIDRMask(p.Bits(), 32)}
}
func host(a netip.Addr) *net.IPNet { return prefix(netip.PrefixFrom(a, 32)) }
func sysctl(name string, value int) error {
	path := "/proc/sys/net/ipv4/" + name
	data, err := os.ReadFile(path) // #nosec G304 -- private callers use fixed IPv4 sysctl names and fixed Ratatoskr device names.
	if err != nil {
		return err
	}
	have, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}
	// Default pod proc mounts may be read-only. Do not write a sysctl that is
	// already correct, or turn disabled reverse-path filtering into a new
	// restriction. Strict filtering requires a real writable change and fails
	// explicitly if the init driver's runtime cannot allow it.
	if have == value || (strings.HasSuffix(name, "/rp_filter") && have == 0) {
		return nil
	}
	return os.WriteFile(path, []byte(strconv.Itoa(value)), 0600)
}
func fallback(table int) netlink.Route {
	return netlink.Route{Family: unix.AF_INET, Dst: prefix(netip.MustParsePrefix("0.0.0.0/0")), Table: table, Type: unix.RTN_UNREACHABLE, Priority: fallbackMetric, Protocol: datapath.RouteProtocol}
}
func (b *Backend) rule(r *netlink.Rule) error {
	r.Family = unix.AF_INET
	r.Protocol = datapath.RouteProtocol
	r.Type = unix.RTN_UNICAST
	all, err := b.h.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}
	for _, old := range all {
		if old.Priority != r.Priority {
			continue
		}
		sameDst := (old.Dst == nil && r.Dst == nil) || (old.Dst != nil && r.Dst != nil && old.Dst.String() == r.Dst.String())
		sameMask := (old.Mask == nil && r.Mask == nil) || (old.Mask != nil && r.Mask != nil && *old.Mask == *r.Mask)
		// netlink v1.3.1 RuleList does not decode the rtmsg action into Type;
		// it is always zero. Match our explicit protocol tag and all selectors,
		// accepting the absent decoded action (or a decoded lookup action).
		if old.Protocol == r.Protocol && (old.Type == 0 || old.Type == r.Type) && old.Table == r.Table && old.Mark == r.Mark && sameMask && sameDst && old.IifName == r.IifName && old.OifName == r.OifName && old.Src == nil && old.Tos == 0 && old.TunID == 0 && old.Dport == nil && old.Sport == nil && old.UIDRange == nil && old.IPProto == 0 && !old.Invert && old.Goto == r.Goto && old.SuppressIfgroup == r.SuppressIfgroup && old.SuppressPrefixlen == r.SuppressPrefixlen {
			return nil
		}
		return fmt.Errorf("routing rule priority %d is already occupied", r.Priority)
	}
	if err := b.h.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}
func (b *Backend) ownedClientRules() ([]netlink.Rule, error) {
	all, err := b.h.RuleList(unix.AF_INET)
	if err != nil {
		return nil, err
	}
	var out []netlink.Rule
	for _, r := range all {
		if r.Protocol == datapath.RouteProtocol && r.Priority >= metadataPriority && r.Priority <= datapath.RulePriority+999 {
			out = append(out, r)
		}
	}
	return out, nil
}
func exclusionRules(c datapath.ClientConfig) []*netlink.Rule {
	set := map[netip.Prefix]bool{}
	for _, p := range c.Exclusions {
		set[p.Masked()] = true
	}
	for _, p := range c.Policy.ExcludeCIDRs {
		set[p.Masked()] = true
	}
	// Never recursively steer encapsulated packets to their own gateway.
	if c.Endpoint.IsValid() {
		set[netip.PrefixFrom(c.Endpoint, 32)] = true
	}
	set[netip.MustParsePrefix("169.254.0.0/16")] = true
	ps := make([]netip.Prefix, 0, len(set))
	for p := range set {
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].String() < ps[j].String() })
	out := make([]*netlink.Rule, 0, len(ps))
	for i, p := range ps {
		r := netlink.NewRule()
		r.Priority = datapath.RulePriority + i
		r.Table = unix.RT_TABLE_MAIN
		r.Dst = prefix(p)
		out = append(out, r)
	}
	return out
}

// clientFirewall owns the client MSS and IPv4 steering nft tables, replacing
// their prior contents in one batch.
// route/output reroutes on mark changes; filter/output does not reroute.
func (b *Backend) clientFirewall(c datapath.ClientConfig) error {
	conn, t, err := b.table("ratatoskr")
	if err != nil {
		return err
	}
	mss := conn.AddChain(&nftables.Chain{Name: "mss", Table: t, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityMangle})
	if c.Endpoint.IsValid() {
		conn.AddRule(&nftables.Rule{Table: t, Chain: mss, Exprs: append(matchIface(expr.MetaKeyOIFNAME, datapath.ClientDevice), mssExprs(c.MTU-40)...)})
	}
	// Postrouting sees the final tunnel OIF after route/output has rerouted.
	// IPv4 route chains belong to the IP family (not the INet MSS table).
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	for _, old := range tables {
		if old.Name == "ratatoskr_route" && old.Family == nftables.TableFamilyIPv4 {
			conn.DelTable(old)
		}
	}
	if c.Policy.Mode != "" {
		routeTable := conn.AddTable(&nftables.Table{Name: "ratatoskr_route", Family: nftables.TableFamilyIPv4})
		chain := conn.AddChain(&nftables.Chain{Name: "steer", Table: routeTable, Type: nftables.ChainTypeRoute, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityMangle})
		// Any existing mesh/CNI mark bits outside MarkMask survive the update.
		mark := []expr.Any{&expr.Meta{Key: expr.MetaKeyMARK, Register: 1}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: native32(^datapath.MarkMask), Xor: native32(steeringMark)}, &expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1}}
		for _, r := range c.Policy.Rules {
			dsts := r.CIDRs
			if len(dsts) == 0 {
				dsts = []netip.Prefix{{}}
			}
			ports := r.Ports
			if len(ports) == 0 {
				ports = []datapath.Port{{}}
			}
			for _, dst := range dsts {
				for _, port := range ports {
					x := make([]expr.Any, 0, 10)
					if dst.IsValid() {
						addr := dst.Masked().Addr().As4()
						mask := net.CIDRMask(dst.Bits(), 32)
						x = append(x, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr[:]})
					}
					if port.Port != 0 {
						proto := byte(unix.IPPROTO_TCP)
						if port.Protocol == "UDP" {
							proto = unix.IPPROTO_UDP
						}
						x = append(x, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, port.Port)})
					}
					if c.Policy.Mode == "include" {
						x = append(x, mark...)
					} else {
						x = append(x, &expr.Verdict{Kind: expr.VerdictReturn})
					}
					conn.AddRule(&nftables.Rule{Table: routeTable, Chain: chain, Exprs: x})
				}
			}
		}
		if c.Policy.Mode == "exclude" {
			conn.AddRule(&nftables.Rule{Table: routeTable, Chain: chain, Exprs: mark})
		}
	}
	return conn.Flush()
}
func native32(n uint32) []byte { b := make([]byte, 4); binary.NativeEndian.PutUint32(b, n); return b }

// Reject IPv6-capable pod interfaces rather than silently leaving IPv6 on
// eth0 unsteered. IPv6 steering is outside the v1 datapath contract.
func (b *Backend) rejectDualStack() error {
	link, err := b.h.LinkByName("eth0")
	if isMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	addrs, err := b.h.AddrList(link, unix.AF_INET6)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if a.IP == nil {
			continue
		}
		if v, ok := netip.AddrFromSlice(a.IP); ok && v.Is6() && !v.IsLinkLocalUnicast() && !v.IsUnspecified() {
			return fmt.Errorf("IPv6 address %s on eth0 is unsupported: IPv4-only steering would leak IPv6 traffic", v)
		}
	}
	return nil
}

func (b *Backend) ApplyClient(ctx context.Context, c datapath.ClientConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.rejectDualStack(); err != nil {
		return err
	}
	rs := exclusionRules(c)
	if len(rs) >= 999 {
		return fmt.Errorf("too many exclusions for reserved rule priority band")
	}
	table := datapath.ClientTable(c.GatewayID)
	// The fallback is installed before either catch-all or mark selectors.
	fr := fallback(table)
	if err := b.h.RouteReplace(&fr); err != nil {
		return fmt.Errorf("client fallback: %w", err)
	}
	if !c.Endpoint.IsValid() {
		// Withdraw the old healthy path immediately; never leave a previously
		// programmed unicast default usable while updating nft or the rules.
		routes, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for _, r := range routes {
			if r.Dst == nil && r.Type == unix.RTN_UNICAST && int(r.Protocol) == datapath.RouteProtocol {
				if err := b.h.RouteDel(&r); err != nil {
					return err
				}
			}
		}
	}
	// The metadata rule precedes the link-local main lookup. A dedicated
	// prohibit /32 in our table never changes main or foreign CNI routes.
	mr := netlink.Route{Family: unix.AF_INET, Dst: prefix(metadataIP), Table: table, Type: unix.RTN_PROHIBIT, Protocol: datapath.RouteProtocol}
	if !c.AllowCloudMetadata {
		if err := b.h.RouteReplace(&mr); err != nil {
			return fmt.Errorf("metadata prohibit: %w", err)
		}
	}
	steer := netlink.NewRule()
	steer.Priority = datapath.RulePriority + 999
	steer.Table = table
	if c.Policy.Mode != "" {
		steer.Priority = datapath.RulePriority + 998
		steer.Mark = steeringMark
		mask := datapath.MarkMask
		steer.Mask = &mask
	}
	// Install the catch-all before withdrawing an old selective nft chain.
	// In the opposite direction, install nft before removing the catch-all.
	if c.Policy.Mode == "" {
		if err := b.rule(steer); err != nil {
			return fmt.Errorf("client steering rule: %w", err)
		}
	}
	if err := b.clientFirewall(c); err != nil {
		return fmt.Errorf("client firewall: %w", err)
	}
	// Distinct priorities keep the old steering rule active until the new
	// selector exists: switching full -> selective cannot leak via main.
	if err := b.rule(steer); err != nil {
		return fmt.Errorf("client steering rule: %w", err)
	}
	// Remove stale exemptions only after the new steering selector is active.
	old, err := b.ownedClientRules()
	if err != nil {
		return err
	}
	for _, r := range old {
		if r.Priority != steer.Priority {
			if err := b.h.RuleDel(&r); err != nil {
				return err
			}
		}
	}
	if !c.AllowCloudMetadata {
		meta := netlink.NewRule()
		meta.Priority = metadataPriority
		meta.Table = table
		meta.Dst = prefix(metadataIP)
		if err := b.rule(meta); err != nil {
			return err
		}
	} else {
		// The higher-priority metadata selector is gone before its route.
		routes, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for _, r := range routes {
			if r.Dst != nil && r.Dst.String() == metadataIP.String() && int(r.Protocol) == datapath.RouteProtocol {
				if err := b.h.RouteDel(&r); err != nil {
					return err
				}
			}
		}
	}
	for _, r := range rs {
		if err := b.rule(r); err != nil {
			return err
		}
	}
	link, err := b.h.LinkByName(datapath.ClientDevice)
	if !c.Endpoint.IsValid() {
		if err == nil {
			if err := b.h.LinkDel(link); err != nil {
				return err
			}
		}
		if err != nil && !isMissing(err) {
			return err
		}
		return nil
	}
	if err != nil && !isMissing(err) {
		return err
	}
	if err == nil {
		g, ok := link.(*netlink.Geneve)
		if !ok {
			return fmt.Errorf("%s is not GENEVE", datapath.ClientDevice)
		}
		if g.ID != c.GatewayID || !g.Remote.Equal(ip(c.Endpoint)) || g.FlowBased {
			if err := b.h.LinkDel(link); err != nil {
				return err
			}
			link = nil
		}
	}
	if link == nil {
		mac, _ := net.ParseMAC(datapath.ClientMAC)
		g := &netlink.Geneve{LinkAttrs: netlink.LinkAttrs{Name: datapath.ClientDevice, MTU: c.MTU, HardwareAddr: mac}, ID: c.GatewayID, Remote: ip(c.Endpoint), Dport: datapath.GenevePort, UdpCsum: 1}
		if err := b.h.LinkAdd(g); err != nil {
			return fmt.Errorf("create client GENEVE: %w", err)
		}
		link, err = b.h.LinkByName(datapath.ClientDevice)
		if err != nil {
			return err
		}
	}
	if err := b.h.LinkSetMTU(link, c.MTU); err != nil {
		return err
	}
	if err := sysctl("conf/all/rp_filter", 2); err != nil {
		return err
	}
	if err := sysctl("conf/"+datapath.ClientDevice+"/rp_filter", 2); err != nil {
		return err
	}
	if err := b.h.LinkSetUp(link); err != nil {
		return err
	}
	mac, _ := net.ParseMAC(datapath.GatewayMAC)
	if err := b.h.NeighSet(&netlink.Neigh{LinkIndex: link.Attrs().Index, IP: net.ParseIP("169.254.64.1"), HardwareAddr: mac, State: netlink.NUD_PERMANENT}); err != nil {
		return err
	}
	r := netlink.Route{Family: unix.AF_INET, Table: table, LinkIndex: link.Attrs().Index, Gw: net.ParseIP("169.254.64.1"), Src: ip(c.PodIP), Flags: unix.RTNH_F_ONLINK, Protocol: datapath.RouteProtocol, MTU: c.MTU}
	if err := b.h.RouteReplace(&r); err != nil {
		return fmt.Errorf("client tunnel default: %w", err)
	}
	return ctx.Err()
}
func isMissing(err error) bool {
	var e netlink.LinkNotFoundError
	return errors.As(err, &e) || errors.Is(err, unix.ENODEV)
}

func (b *Backend) RemoveClient(ctx context.Context, c datapath.ClientConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rs, err := b.ownedClientRules()
	if err != nil {
		return err
	}
	// Removal is an explicit opt-out: only now restore the main route lookup.
	for _, r := range rs {
		if err := b.h.RuleDel(&r); err != nil {
			return err
		}
	}
	if l, err := b.h.LinkByName(datapath.ClientDevice); err == nil {
		if err := b.h.LinkDel(l); err != nil {
			return err
		}
	} else if !isMissing(err) {
		return err
	}
	conn := b.nft()
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	for _, t := range tables {
		if (t.Name == "ratatoskr" && t.Family == nftables.TableFamilyINet) || (t.Name == "ratatoskr_route" && t.Family == nftables.TableFamilyIPv4) {
			conn.DelTable(t)
		}
	}
	if err := conn.Flush(); err != nil {
		return err
	}
	routes, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: datapath.ClientTable(c.GatewayID)}, netlink.RT_FILTER_TABLE)
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
