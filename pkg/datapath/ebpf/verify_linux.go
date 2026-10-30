//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	cebpf "github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// VerifyClient checks kernel attachment and the attached program's actual maps,
// including after node-agent process restart when this Backend has no Go-held
// program/map file descriptors. It never treats a tc filter name alone as proof.
func (b *Backend) VerifyClient(ctx context.Context, c datapath.ClientConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Encryption == "wireguard" {
		return fmt.Errorf("ebpf cannot verify WireGuard client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	eth, err := b.h.LinkByName("eth0")
	if err != nil {
		return err
	}
	if err := b.checkEgressFilters(eth); err != nil {
		return err
	}
	if guard, err := b.findUpdateGuard(eth); err != nil {
		return err
	} else if guard != nil {
		return fmt.Errorf("ebpf update guard still installed; reject restart adoption")
	}
	for _, device := range []string{datapath.ClientDevice, datapath.WireGuardDevice} {
		if _, err := b.h.LinkByName(device); err == nil {
			return fmt.Errorf("unexpected client tunnel device %s", device)
		} else {
			var missing netlink.LinkNotFoundError
			if !errors.As(err, &missing) {
				return err
			}
		}
	}
	rules, err := b.h.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.Protocol == datapath.RouteProtocol && r.Priority >= datapath.RulePriority && r.Priority <= datapath.RulePriority+999 {
			return fmt.Errorf("iproute steering rule remains alongside ebpf selector")
		}
	}
	filters, err := b.h.FilterList(eth, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return err
	}
	var attached *netlink.BpfFilter
	for _, f := range filters {
		if bf, ok := f.(*netlink.BpfFilter); ok && f.Attrs().Priority == filterPriority && f.Attrs().Handle == filterHandle && bf.Name == "ratatoskr_ebpf" && bf.DirectAction && f.Attrs().Protocol == unix.ETH_P_ALL {
			attached = bf
			break
		}
	}
	if attached == nil || attached.Id <= 0 || uint64(attached.Id) > uint64(^uint32(0)) || attached.Tag == "" {
		return fmt.Errorf("ebpf tc selector missing program identity")
	}
	program, err := cebpf.NewProgramFromID(cebpf.ProgramID(attached.Id))
	if err != nil {
		return fmt.Errorf("open attached ebpf program: %w", err)
	}
	defer program.Close()
	info, err := program.Info()
	if err != nil {
		return err
	}
	if info.Type != cebpf.SchedCLS || info.Tag != attached.Tag {
		return fmt.Errorf("tc selector program tag/type differs from attached ebpf program")
	}
	if b.objects != nil {
		active, err := b.objects.Steer.Info()
		if err != nil {
			return err
		}
		activeID, ok := active.ID()
		if !ok {
			return fmt.Errorf("ebpf program ID unavailable")
		}
		attachedID, ok := info.ID()
		if !ok || activeID != attachedID {
			return fmt.Errorf("attached program differs from current ebpf backend")
		}
	}
	ids, ok := info.MapIDs()
	if !ok {
		return fmt.Errorf("kernel lacks attached ebpf map IDs")
	}
	handles := map[string]*cebpf.Map{}
	defer func() {
		for _, m := range handles {
			_ = m.Close()
		}
	}()
	for _, id := range ids {
		m, err := cebpf.NewMapFromID(id)
		if err != nil {
			return err
		}
		mi, err := m.Info()
		if err != nil {
			_ = m.Close()
			return err
		}
		if _, exists := handles[mi.Name]; exists {
			_ = m.Close()
			return fmt.Errorf("duplicate ebpf map %s", mi.Name)
		}
		handles[mi.Name] = m
	}
	for _, name := range []string{"config", "identity", "exclude_v4", "include_v4", "port_rules", "rules", "stats"} {
		if handles[name] == nil {
			return fmt.Errorf("missing attached ebpf map %s", name)
		}
	}
	expected := clientClientConfig{PodIp: addrU32(c.PodIP), GatewayId: c.GatewayID, GatewayMac: [6]byte{2, 0x52, 0x54, 0x4b, 0, 2}}
	if c.AllowCloudMetadata {
		expected.AllowMetadata = 1
	}
	switch c.Policy.Mode {
	case "include":
		expected.Mode = 1
	case "exclude":
		expected.Mode = 2
	}
	if c.Endpoint.IsValid() {
		geneve, err := b.h.LinkByName(datapath.GatewayDevice)
		if err != nil {
			return err
		}
		g, ok := geneve.(*netlink.Geneve)
		if !ok || !g.FlowBased || g.Dport != datapath.GenevePort || g.Attrs().MTU != c.MTU || g.Attrs().Flags&net.FlagUp == 0 {
			return fmt.Errorf("ebpf external GENEVE link inconsistent")
		}
		if err := b.verifyGeneveAddress(geneve); err != nil {
			return err
		}
		expected.Ifindex = uint32(geneve.Attrs().Index) // #nosec G115 -- kernel ifindex fits u32.
		expected.Endpoint = uint32FromEndpoint(c.Endpoint)
		expected.Healthy = 1
		routes, err := b.h.RouteGet(net.IP(c.Endpoint.AsSlice()))
		if err != nil {
			return err
		}
		if len(routes) == 0 || !routes[0].Src.Equal(net.IP(c.PodIP.AsSlice())) {
			return fmt.Errorf("GENEVE underlay no longer sources client pod IP")
		}
	}
	var configured clientClientConfig
	if err := handles["config"].Lookup(uint32(0), &configured); err != nil {
		return err
	}
	if configured != expected {
		return fmt.Errorf("attached ebpf config differs from selected endpoint or policy")
	}
	var identity clientGeneveOpt
	if err := handles["identity"].Lookup(uint32(0), &identity); err != nil {
		return err
	}
	if identity != identityTLV(c) {
		return fmt.Errorf("attached ebpf identity TLV differs")
	}
	exclusions := map[netip.Prefix]bool{netip.MustParsePrefix("169.254.0.0/16"): true}
	if c.Endpoint.IsValid() {
		exclusions[netip.PrefixFrom(c.Endpoint, 32)] = true
	}
	for _, p := range c.Exclusions {
		exclusions[p.Masked()] = true
	}
	for _, p := range c.Policy.ExcludeCIDRs {
		exclusions[p.Masked()] = true
	}
	wantedExclude := map[clientLpmV4]uint8{}
	for p := range exclusions {
		wantedExclude[prefixKey(p)] = 1
	}
	if err := equalMap(handles["exclude_v4"], wantedExclude); err != nil {
		return fmt.Errorf("exclude_v4: %w", err)
	}
	wantedDst := map[clientLpmRule]uint8{}
	wantedPorts := map[clientPortKey]uint8{}
	for i, r := range c.Policy.Rules {
		info := clientRuleInfo{Active: 1}
		if len(r.CIDRs) == 0 {
			info.AnyDst = 1
		}
		if len(r.Ports) == 0 {
			info.AnyPort = 1
		}
		var actual clientRuleInfo
		if err := handles["rules"].Lookup(uint32(i), &actual); err != nil {
			return err
		}
		if actual != info {
			return fmt.Errorf("ebpf policy rule %d changed", i)
		}
		for _, p := range r.CIDRs {
			wantedDst[ruleKey(uint32(i), p)] = 1
		} // #nosec G115 -- <=64 rules.
		for _, p := range r.Ports {
			proto := uint8(6)
			if p.Protocol == "UDP" {
				proto = 17
			}
			wantedPorts[clientPortKey{Rule: uint32(i), Proto: proto, Port: p.Port}] = 1
		} // #nosec G115 -- <=64 rules.
	}
	for i := len(c.Policy.Rules); i < 64; i++ {
		var r clientRuleInfo
		if err := handles["rules"].Lookup(uint32(i), &r); err != nil {
			return err
		} // #nosec G115 -- i<64.
		if r.Active != 0 {
			return fmt.Errorf("unexpected active ebpf policy rule %d", i)
		}
	}
	if err := equalMap(handles["include_v4"], wantedDst); err != nil {
		return fmt.Errorf("include_v4: %w", err)
	}
	if err := equalMap(handles["port_rules"], wantedPorts); err != nil {
		return fmt.Errorf("port_rules: %w", err)
	}
	return ctx.Err()
}
func uint32FromEndpoint(a netip.Addr) uint32 {
	return uint32(a.As4()[0])<<24 | uint32(a.As4()[1])<<16 | uint32(a.As4()[2])<<8 | uint32(a.As4()[3])
}
func equalMap[K comparable](m *cebpf.Map, expected map[K]uint8) error {
	got := map[K]uint8{}
	it := m.Iterate()
	var k K
	var v uint8
	for it.Next(&k, &v) {
		got[k] = v
	}
	if err := it.Err(); err != nil {
		return err
	}
	if len(got) != len(expected) {
		return fmt.Errorf("attached map entry count %d, want %d", len(got), len(expected))
	}
	for key, want := range expected {
		if got[key] != want {
			return errors.New("attached map contents differ")
		}
	}
	return nil
}
