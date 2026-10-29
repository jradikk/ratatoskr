//go:build linux

// Package iproute implements GENEVE steering using netlink and nftables.
package iproute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

const fallbackMetric = 4294967295

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
		if r.Protocol == datapath.RouteProtocol && r.Priority >= datapath.RulePriority && r.Priority <= datapath.RulePriority+999 {
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

func (b *Backend) ApplyClient(ctx context.Context, c datapath.ClientConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rs := exclusionRules(c)
	if len(rs) >= 999 {
		return fmt.Errorf("too many exclusions for reserved rule priority band")
	}
	table := datapath.ClientTable(c.GatewayID)
	// Install the fail-closed table before any rule can refer to it.
	fr := fallback(table)
	if err := b.h.RouteReplace(&fr); err != nil {
		return fmt.Errorf("client fallback: %w", err)
	}
	catch := netlink.NewRule()
	catch.Priority = datapath.RulePriority + 999
	catch.Table = table
	if err := b.rule(catch); err != nil {
		return fmt.Errorf("client steering rule: %w", err)
	}
	// Restrict traffic during updates by deleting old exemptions first. The
	// catch-all and unreachable fallback remain installed if an update fails.
	old, err := b.ownedClientRules()
	if err != nil {
		return err
	}
	for _, r := range old {
		if r.Priority != catch.Priority {
			if err := b.h.RuleDel(&r); err != nil {
				return err
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
	if err := b.clientMSS(c.MTU - 40); err != nil {
		return fmt.Errorf("client MSS: %w", err)
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
		if t.Name == "ratatoskr" && t.Family == nftables.TableFamilyINet {
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
