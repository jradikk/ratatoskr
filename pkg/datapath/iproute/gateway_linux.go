//go:build linux

package iproute

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// ApplyGateway keeps the pod's main routing table untouched. Forwarded packets
// and explicitly marked upstream health probes are the only table-100 users.
func (b *Backend) ApplyGateway(ctx context.Context, c datapath.GatewayConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Default-drop must exist before we enable forwarding or change routes.
	if err := b.gatewayFirewall(false, c.MTU-40); err != nil {
		return fmt.Errorf("gateway kill switch: %w", err)
	}
	for _, table := range []int{datapath.GatewayTable, datapath.ReturnTable} {
		r := fallback(table)
		if err := b.h.RouteReplace(&r); err != nil {
			return err
		}
	}
	link, err := b.h.LinkByName(datapath.GatewayDevice)
	if err != nil && !isMissing(err) {
		return err
	}
	if err == nil {
		g, ok := link.(*netlink.Geneve)
		if !ok || !g.FlowBased {
			return fmt.Errorf("%s must be collect_md GENEVE", datapath.GatewayDevice)
		}
	}
	if link == nil {
		mac, _ := net.ParseMAC(datapath.GatewayMAC)
		g := &netlink.Geneve{LinkAttrs: netlink.LinkAttrs{Name: datapath.GatewayDevice, MTU: c.MTU, HardwareAddr: mac}, FlowBased: true, Dport: datapath.GenevePort, UdpCsum: 1}
		if err := b.h.LinkAdd(g); err != nil {
			return fmt.Errorf("create gateway GENEVE: %w", err)
		}
		link, err = b.h.LinkByName(datapath.GatewayDevice)
		if err != nil {
			return err
		}
	}
	if err := b.verifier(link, c); err != nil {
		return fmt.Errorf("gateway spoof verifier: %w", err)
	}
	if err := b.h.LinkSetMTU(link, c.MTU); err != nil {
		return err
	}
	if err := b.h.LinkSetUp(link); err != nil {
		return err
	}
	// ip_forward resets IPv4 device settings, so set it before rp_filter.
	if err := sysctl("ip_forward", 1); err != nil {
		return err
	}
	if err := sysctl("conf/all/rp_filter", 2); err != nil {
		return err
	}
	if err := sysctl("conf/"+datapath.GatewayDevice+"/rp_filter", 2); err != nil {
		return err
	}
	for _, v := range []struct {
		priority, table int
		iif             string
		mark            uint32
	}{{9000, datapath.GatewayTable, "", datapath.ProbeMark}, {9001, datapath.GatewayTable, datapath.GatewayDevice, 0}, {9002, datapath.ReturnTable, datapath.UpstreamDevice, 0}} {
		r := netlink.NewRule()
		r.Priority = v.priority
		r.Table = v.table
		r.IifName = v.iif
		if v.mark != 0 {
			r.Mark = v.mark
			mask := datapath.MarkMask
			r.Mask = &mask
		}
		if err := b.rule(r); err != nil {
			return fmt.Errorf("gateway routing rule: %w", err)
		}
	}
	// Refresh only Ratatoskr-owned return routes. Keep unreachable in place.
	old, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: datapath.ReturnTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, r := range old {
		if r.Type == unix.RTN_UNICAST && int(r.Protocol) == datapath.RouteProtocol {
			if err := b.h.RouteDel(&r); err != nil {
				return err
			}
		}
	}
	mac, _ := net.ParseMAC(datapath.ClientMAC)
	for _, client := range c.Clients {
		if err := b.h.NeighSet(&netlink.Neigh{LinkIndex: link.Attrs().Index, IP: ip(client), HardwareAddr: mac, State: netlink.NUD_PERMANENT}); err != nil {
			return err
		}
		r := netlink.Route{Family: unix.AF_INET, Table: datapath.ReturnTable, Dst: host(client), LinkIndex: link.Attrs().Index, Scope: netlink.SCOPE_LINK, Protocol: datapath.RouteProtocol, MTU: c.MTU, Encap: &ipEncap{ID: uint64(c.GatewayID), Src: c.PodIP, Dst: client}}
		if err := b.h.RouteReplace(&r); err != nil {
			return fmt.Errorf("gateway return route: %w", err)
		}
	}
	up, err := b.h.LinkByName(datapath.UpstreamDevice)
	healthy := false
	mss := c.MTU - 40
	if err == nil && up.Attrs().Flags&net.FlagUp != 0 {
		if up.Attrs().MTU < 576 {
			return fmt.Errorf("upstream MTU below IPv4 minimum")
		}
		if up.Attrs().MTU < c.MTU {
			mss = up.Attrs().MTU - 40
		}
		// Keep this route during health failure: probes need it to recover. Only
		// the FORWARD hook is gated; marked local health probes still work.
		r := netlink.Route{Family: unix.AF_INET, Dst: prefix(netip.MustParsePrefix("0.0.0.0/0")), Table: datapath.GatewayTable, LinkIndex: up.Attrs().Index, Protocol: datapath.RouteProtocol}
		if err := b.h.RouteReplace(&r); err != nil {
			return err
		}
		healthy = c.UpstreamHealthy
	} else if err != nil && !isMissing(err) {
		return err
	}
	if err := b.gatewayFirewall(healthy, mss); err != nil {
		return err
	}
	return ctx.Err()
}

func (b *Backend) verifier(link netlink.Link, c datapath.GatewayConfig) error {
	q := &netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_INGRESS}}
	if err := b.h.QdiscAdd(q); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("ingress qdisc: %w", err)
	}
	parent := netlink.MakeHandle(0xffff, 0)
	old, err := b.h.FilterList(link, parent)
	if err != nil {
		return err
	}
	dropInstalled := false
	for _, f := range old {
		if f.Attrs().Priority == 65535 {
			dropInstalled = true
		}
	}
	if !dropInstalled {
		drop := &netlink.MatchAll{FilterAttrs: netlink.FilterAttrs{LinkIndex: link.Attrs().Index, Parent: parent, Priority: 65535, Protocol: unix.ETH_P_ALL}, Actions: []netlink.Action{&netlink.GenericAction{ActionAttrs: netlink.ActionAttrs{Action: netlink.TC_ACT_SHOT}}}}
		if err := b.h.FilterAdd(drop); err != nil {
			return fmt.Errorf("default-drop filter: %w", err)
		}
	}
	for _, f := range old {
		if f.Attrs().Priority >= 10 && f.Attrs().Priority < 65535 {
			if err := b.h.FilterDel(f); err != nil {
				return err
			}
		}
	}
	// All allowed pods use one mask/priority so flower performs a hashed lookup.
	// SkipHw is deliberately omitted: v1.3.1 encodes flower flags in network
	// order, while the kernel expects native order; virtual GENEVE has no HW
	// offload path to bypass the software verifier.
	for _, client := range c.Clients {
		f := &netlink.Flower{FilterAttrs: netlink.FilterAttrs{LinkIndex: link.Attrs().Index, Parent: parent, Priority: 10, Protocol: unix.ETH_P_IP}, SrcIP: ip(client), EncSrcIP: ip(client), EncKeyId: c.GatewayID, Actions: []netlink.Action{&netlink.GenericAction{ActionAttrs: netlink.ActionAttrs{Action: netlink.TC_ACT_OK}}}}
		if err := b.h.FilterAdd(f); err != nil {
			return fmt.Errorf("source verification filter: %w", err)
		}
	}
	return nil
}

// ipEncap is the kernel LWTUNNEL_ENCAP_IP metadata encoding used with an external
// GENEVE device (equivalent to `ip route ... encap ip id ID src S dst D`). The
// netlink library exposes Encap but does not ship this IPv4 implementation.
type ipEncap struct {
	ID       uint64
	Src, Dst netip.Addr
}

func (*ipEncap) Type() int                        { return 2 }
func (e *ipEncap) String() string                 { return fmt.Sprintf("ip id %d src %s dst %s", e.ID, e.Src, e.Dst) }
func (e *ipEncap) Equal(other netlink.Encap) bool { o, ok := other.(*ipEncap); return ok && *e == *o }
func (*ipEncap) Decode([]byte) error              { return fmt.Errorf("IPv4 LWT decoding is not used") }
func (e *ipEncap) Encode() ([]byte, error) {
	id := make([]byte, 8)
	binary.BigEndian.PutUint64(id, e.ID)
	// Attribute identifiers are from Linux uapi/linux/lwtunnel.h. Tunnel key
	// flag is stored in network byte order (uapi/linux/if_tunnel.h).
	attrs := []*nl.RtAttr{nl.NewRtAttr(1, id), nl.NewRtAttr(2, ip(e.Dst)), nl.NewRtAttr(3, ip(e.Src)), nl.NewRtAttr(6, []byte{0, 4})}
	var out []byte
	for _, a := range attrs {
		out = append(out, a.Serialize()...)
	}
	return out, nil
}

func (b *Backend) table(name string) (*nftables.Conn, *nftables.Table, error) {
	conn := b.nft()
	tables, err := conn.ListTables()
	if err != nil {
		return nil, nil, err
	}
	for _, t := range tables {
		if t.Name == name && t.Family == nftables.TableFamilyINet {
			conn.DelTable(t)
		}
	}
	t := conn.AddTable(&nftables.Table{Name: name, Family: nftables.TableFamilyINet})
	return conn, t, nil
}
func matchIface(key expr.MetaKey, name string) []expr.Any {
	return []expr.Any{&expr.Meta{Key: key, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(name), 0)}}
}
func mssExprs(mss int) []expr.Any {
	v := binary.BigEndian.AppendUint16(nil, uint16(mss)) // #nosec G115 -- validated IPv4 MTU is 576..65535; MSS is MTU-40.
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{2}, Xor: []byte{0}}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}}, &expr.Exthdr{DestRegister: 1, Type: 2, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt}, &expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: v}, &expr.Immediate{Register: 1, Data: v}, &expr.Exthdr{SourceRegister: 1, Type: 2, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt}}
}
func (b *Backend) clientMSS(mss int) error {
	conn, t, err := b.table("ratatoskr")
	if err != nil {
		return err
	}
	chain := conn.AddChain(&nftables.Chain{Name: "mss", Table: t, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityMangle})
	x := append(matchIface(expr.MetaKeyOIFNAME, datapath.ClientDevice), mssExprs(mss)...)
	conn.AddRule(&nftables.Rule{Table: t, Chain: chain, Exprs: x})
	return conn.Flush()
}
func (b *Backend) gatewayFirewall(healthy bool, mss int) error {
	conn, t, err := b.table("ratatoskr_gw")
	if err != nil {
		return err
	}
	drop := nftables.ChainPolicyDrop
	chain := conn.AddChain(&nftables.Chain{Name: "forward", Table: t, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &drop})
	if healthy {
		for _, pair := range [][2]string{{datapath.GatewayDevice, datapath.UpstreamDevice}, {datapath.UpstreamDevice, datapath.GatewayDevice}} {
			x := append(matchIface(expr.MetaKeyIIFNAME, pair[0]), matchIface(expr.MetaKeyOIFNAME, pair[1])...)
			conn.AddRule(&nftables.Rule{Table: t, Chain: chain, Exprs: append(append([]expr.Any{}, x...), mssExprs(mss)...)})
			if pair[0] == datapath.UpstreamDevice {
				state := make([]byte, 4)
				binary.NativeEndian.PutUint32(state, expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED)
				x = append(x, &expr.Ct{Key: expr.CtKeySTATE, Register: 1}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: state, Xor: make([]byte, 4)}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)})
			}
			x = append(x, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept})
			conn.AddRule(&nftables.Rule{Table: t, Chain: chain, Exprs: x})
		}
	}
	// Default-drop accounting is present even while no upstream is healthy.
	conn.AddRule(&nftables.Rule{Table: t, Chain: chain, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}})
	nat := conn.AddChain(&nftables.Chain{Name: "snat", Table: t, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource})
	x := append(matchIface(expr.MetaKeyIIFNAME, datapath.GatewayDevice), matchIface(expr.MetaKeyOIFNAME, datapath.UpstreamDevice)...)
	x = append(x, &expr.Masq{})
	conn.AddRule(&nftables.Rule{Table: t, Chain: nat, Exprs: x})
	return conn.Flush()
}
