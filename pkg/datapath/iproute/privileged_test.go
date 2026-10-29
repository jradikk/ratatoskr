//go:build linux && privileged

package iproute

import (
	"context"
	"net"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func isolated(t *testing.T, fn func(*Backend)) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("privileged tests require root")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(orig); err != nil {
			t.Errorf("restore netns: %v", err)
		}
		_ = ns.Close()
	}()
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	fn(b)
}
func dummy(t *testing.T, b *Backend, name, addr string) netlink.Link {
	t.Helper()
	l := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: 1500}}
	if err := b.h.LinkAdd(l); err != nil {
		t.Fatal(err)
	}
	link, err := b.h.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.h.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	if addr != "" {
		a, err := netlink.ParseAddr(addr)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.AddrAdd(link, a); err != nil {
			t.Fatal(err)
		}
	}
	return link
}
func mainRoutes(t *testing.T, b *Backend) []netlink.Route {
	t.Helper()
	r, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestPrivilegedClient(t *testing.T) {
	isolated(t, func(b *Backend) {
		eth := dummy(t, b, "eth0", "10.42.1.8/24")
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: net.ParseIP("10.42.1.1")}); err != nil {
			t.Fatal(err)
		}
		before := mainRoutes(t, b)
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), Endpoint: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 1400, Exclusions: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}}
		for i := 0; i < 2; i++ {
			if err := b.ApplyClient(context.Background(), c); err != nil {
				t.Fatal(err)
			}
		}
		rs, err := b.ownedClientRules()
		if err != nil {
			t.Fatal(err)
		}
		if len(rs) != 5 {
			t.Fatalf("rules duplicated: %d", len(rs))
		}
		if !reflect.DeepEqual(before, mainRoutes(t, b)) {
			t.Fatal("main routes changed")
		}
		l, err := b.h.LinkByName(datapath.ClientDevice)
		if err != nil {
			t.Fatal(err)
		}
		if g := l.(*netlink.Geneve); g.ID != 7 || g.Attrs().MTU != 1400 || g.Dport != 6081 {
			t.Fatal("incorrect GENEVE device")
		}
		c.Endpoint = netip.Addr{}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if _, err := b.h.RouteGet(net.ParseIP("203.0.113.12")); err == nil {
			t.Fatal("missing endpoint fell through to main")
		}
		if err := b.RemoveClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if _, err := b.h.RouteGet(net.ParseIP("203.0.113.12")); err != nil {
			t.Fatalf("explicit opt-out did not restore main: %v", err)
		}
	})
}
func TestPrivilegedPreservesForeignRules(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b, "eth0", "10.42.1.8/24")
		foreign := netlink.NewRule()
		foreign.Family = unix.AF_INET
		foreign.Priority = datapath.RulePriority + 50
		foreign.Table = 200
		foreign.Mark = 0x40000000
		mask := uint32(0x40000000)
		foreign.Mask = &mask
		foreign.Protocol = 99
		if err := b.h.RuleAdd(foreign); err != nil {
			t.Fatal(err)
		}
		cfg := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400}
		for i := 0; i < 2; i++ {
			if err := b.ApplyClient(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
		}
		if err := b.RemoveClient(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		rules, err := b.h.RuleList(unix.AF_INET)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range rules {
			if r.Priority == foreign.Priority && r.Protocol == 99 && r.Mark == foreign.Mark && r.Table == 200 {
				found = true
			}
		}
		if !found {
			t.Fatal("Ratatoskr modified or deleted a foreign CNI/mesh rule")
		}
	})
}

func TestPrivilegedGateway(t *testing.T) {
	isolated(t, func(b *Backend) {
		eth := dummy(t, b, "eth0", "10.42.2.4/24")
		dummy(t, b, datapath.UpstreamDevice, "198.18.0.2/24")
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: net.ParseIP("10.42.2.1")}); err != nil {
			t.Fatal(err)
		}
		before := mainRoutes(t, b)
		c := datapath.GatewayConfig{PodIP: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 1400, Clients: []netip.Addr{netip.MustParseAddr("10.42.1.8"), netip.MustParseAddr("10.42.1.9")}, UpstreamHealthy: true}
		for i := 0; i < 2; i++ {
			if err := b.ApplyGateway(context.Background(), c); err != nil {
				t.Fatal(err)
			}
		}
		if !reflect.DeepEqual(before, mainRoutes(t, b)) {
			t.Fatal("gateway main routes changed")
		}
		l, err := b.h.LinkByName(datapath.GatewayDevice)
		if err != nil {
			t.Fatal(err)
		}
		fs, err := b.h.FilterList(l, netlink.MakeHandle(0xffff, 0))
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) != 3 {
			t.Fatalf("verifier filters: %d", len(fs))
		}
		found := map[string]bool{}
		for _, f := range fs {
			if flower, ok := f.(*netlink.Flower); ok {
				if !flower.EncSrcIP.Equal(flower.SrcIP) || flower.EncKeyId != c.GatewayID || flower.Attrs().Priority != 10 {
					t.Fatal("missing outer/inner/VNI hashed spoof check")
				}
				found[flower.SrcIP.String()] = true
			}
		}
		for _, client := range c.Clients {
			if !found[client.String()] {
				t.Fatal("selected client missing from verifier")
			}
		}
		c.UpstreamHealthy = false
		if err := b.ApplyGateway(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		conn := b.nft()
		chains, err := conn.ListChains()
		if err != nil {
			t.Fatal(err)
		}
		var forward *nftables.Chain
		for _, ch := range chains {
			if ch.Table.Name == "ratatoskr_gw" && ch.Name == "forward" {
				forward = ch
			}
		}
		if forward == nil || forward.Policy == nil || *forward.Policy != nftables.ChainPolicyDrop {
			t.Fatal("missing default drop")
		}
		rules, err := conn.GetRules(forward.Table, forward)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			for _, e := range r.Exprs {
				if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictAccept {
					t.Fatal("unhealthy upstream still accepts forwarded packets")
				}
			}
		}
		upRoutes, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: datapath.GatewayTable}, netlink.RT_FILTER_TABLE)
		if err != nil || len(upRoutes) < 2 {
			t.Fatalf("recovery probes lost table100 route: %v", err)
		}
	})
}

func TestPrivilegedSelectiveRulesAndMetadata(t *testing.T) {
	isolated(t, func(b *Backend) {
		eth := dummy(t, b, "eth0", "10.42.1.8/24")
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: net.ParseIP("10.42.1.1")}); err != nil {
			t.Fatal(err)
		}
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400, Exclusions: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/16")}, Policy: datapath.Policy{Mode: "include", ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Rules: []datapath.Rule{{CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Ports: []datapath.Port{{Protocol: "TCP", Port: 443}}}}}}
		for _, mode := range []string{"include", "exclude"} {
			c.Policy.Mode = mode
			for i := 0; i < 2; i++ {
				if err := b.ApplyClient(context.Background(), c); err != nil {
					t.Fatal(err)
				}
			}
			rules, err := b.ownedClientRules()
			if err != nil {
				t.Fatal(err)
			}
			if len(rules) != 5 {
				t.Fatalf("%s: unexpected routing rules %d", mode, len(rules))
			}
			var marked bool
			for _, r := range rules {
				if r.Priority == datapath.RulePriority+998 {
					marked = r.Mark == steeringMark && r.Mask != nil && *r.Mask == datapath.MarkMask
				}
			}
			if !marked {
				t.Fatal("missing masked fwmark lookup")
			}
			conn := b.nft()
			chains, err := conn.ListChains()
			if err != nil {
				t.Fatal(err)
			}
			var chain *nftables.Chain
			for _, ch := range chains {
				if ch.Table.Name == "ratatoskr_route" && ch.Name == "steer" {
					chain = ch
				}
			}
			if chain == nil || chain.Type != nftables.ChainTypeRoute || chain.Table.Family != nftables.TableFamilyIPv4 {
				t.Fatal("missing IPv4 route output chain")
			}
			nr, err := conn.GetRules(chain.Table, chain)
			if err != nil {
				t.Fatal(err)
			}
			if len(nr) != 2+map[string]int{"include": 0, "exclude": 1}[mode] {
				t.Fatalf("%s: wrong nft rule count: %d", mode, len(nr))
			}
			for _, ip := range []string{"203.0.113.12", "198.18.0.12"} {
				direct, err := netlink.RouteGetWithOptions(net.ParseIP(ip), &netlink.RouteGetOptions{Mark: steeringMark})
				if err != nil || len(direct) == 0 || direct[0].Table != unix.RT_TABLE_MAIN {
					t.Fatalf("excluded %s did not use main: %v %v", ip, direct, err)
				}
			}
			_, err = netlink.RouteGetWithOptions(net.ParseIP("169.254.169.254"), &netlink.RouteGetOptions{Mark: steeringMark})
			if err == nil {
				t.Fatal("metadata must be prohibited before link-local exemption")
			}
		}
		c.Policy.Rules = nil
		for _, mode := range []string{"include", "exclude"} {
			c.Policy.Mode = mode
			if err := b.ApplyClient(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			conn := b.nft()
			chains, err := conn.ListChains()
			if err != nil {
				t.Fatal(err)
			}
			for _, chain := range chains {
				if chain.Table.Name != "ratatoskr_route" || chain.Name != "steer" {
					continue
				}
				rules, err := conn.GetRules(chain.Table, chain)
				if err != nil {
					t.Fatal(err)
				}
				want := 1 // WG/registration bypass rule always precedes selectors.
				if mode == "exclude" {
					want = 2
				}
				if len(rules) != want {
					t.Fatalf("empty %s should have %d steering rules, got %d", mode, want, len(rules))
				}
			}
		}
		c.AllowCloudMetadata = true
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		r, err := netlink.RouteGetWithOptions(net.ParseIP("169.254.169.254"), &netlink.RouteGetOptions{Mark: steeringMark})
		if err != nil || len(r) == 0 || r[0].Table != unix.RT_TABLE_MAIN {
			t.Fatalf("metadata allowed should use main: %v %v", r, err)
		}
		// Switch through the legacy full tunnel and back: neither mode may
		// leave stale catch-all and selective rules installed together.
		c.Policy.Mode = ""
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		c.Policy.Mode = "exclude"
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		transition, err := b.ownedClientRules()
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range transition {
			if rule.Priority == datapath.RulePriority+999 {
				t.Fatal("stale full-tunnel catch-all after selective transition")
			}
		}
		c.Endpoint = netip.Addr{}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		_, err = netlink.RouteGetWithOptions(net.ParseIP("198.51.100.12"), &netlink.RouteGetOptions{Mark: steeringMark | 0x40000000})
		if err == nil {
			t.Fatal("marked selective traffic fell through to main without endpoint")
		}
		if err := b.RemoveClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPrivilegedRejectDualStackClient(t *testing.T) {
	isolated(t, func(b *Backend) {
		eth := dummy(t, b, "eth0", "10.42.1.8/24")
		v6, err := netlink.ParseAddr("2001:db8::8/64")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.AddrAdd(eth, v6); err != nil {
			t.Fatal(err)
		}
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400}
		if err := b.ApplyClient(context.Background(), c); err == nil {
			t.Fatal("dual-stack pod would bypass IPv4-only steering")
		}
		rules, err := b.ownedClientRules()
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 0 {
			t.Fatal("dual-stack rejection must precede routing changes")
		}
	})
}

func TestPrivilegedWireGuardClient(t *testing.T) {
	isolated(t, func(b *Backend) {
		eth := dummy(t, b, "eth0", "10.42.1.8/24")
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: net.ParseIP("10.42.1.1")}); err != nil {
			t.Fatal(err)
		}
		gatewayPrivate, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), Endpoint: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 1320, Encryption: "wireguard", GatewayPublicKey: gatewayPrivate.PublicKey().String(), RegistrationCACert: "public-test-CA-placeholder"}
		var firstKey string
		for i := 0; i < 2; i++ {
			if err := b.ApplyClient(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			got, err := b.WireGuardPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if firstKey != "" && firstKey != got {
				t.Fatal("client WG key changed on idempotent apply")
			}
			firstKey = got
		}
		dev, err := b.h.LinkByName(datapath.WireGuardDevice)
		if err != nil {
			t.Fatal(err)
		}
		wgRoute, err := netlink.RouteGetWithOptions(net.ParseIP("10.42.2.4"), &netlink.RouteGetOptions{})
		if err != nil || len(wgRoute) != 1 || wgRoute[0].LinkIndex != dev.Attrs().Index || !wgRoute[0].Src.Equal(net.ParseIP("10.42.1.8")) {
			t.Fatalf("WG route must source client pod IP: %v %v", wgRoute, err)
		}
		bypass, err := netlink.RouteGetWithOptions(net.ParseIP("10.42.2.4"), &netlink.RouteGetOptions{Mark: datapath.WireGuardMark})
		if err != nil || len(bypass) != 1 || bypass[0].LinkIndex != eth.Attrs().Index {
			t.Fatalf("WG socket mark did not bypass to main: %v %v", bypass, err)
		}
		conn := b.nft()
		chains, err := conn.ListChains()
		if err != nil {
			t.Fatal(err)
		}
		var input, output *nftables.Chain
		for _, ch := range chains {
			if ch.Table.Name == "ratatoskr_wg" {
				if ch.Name == "input" {
					input = ch
				}
				if ch.Name == "output" {
					output = ch
				}
			}
		}
		if input == nil || output == nil {
			t.Fatal("missing plaintext GENEVE guards")
		}
		for _, chain := range []*nftables.Chain{input, output} {
			rules, err := conn.GetRules(chain.Table, chain)
			if err != nil || len(rules) != 1 {
				t.Fatalf("invalid plaintext GENEVE guard: %v %v", rules, err)
			}
		}
		c.Endpoint = netip.Addr{}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		_, err = netlink.RouteGetWithOptions(net.ParseIP("203.0.113.7"), &netlink.RouteGetOptions{})
		if err == nil {
			t.Fatal("unhealthy gateway must not fall through")
		}
		if err := b.RemoveClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPrivilegedWireGuardGatewayPeers(t *testing.T) {
	isolated(t, func(b *Backend) {
		eth := dummy(t, b, "eth0", "10.42.2.4/24")
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: net.ParseIP("10.42.2.1")}); err != nil {
			t.Fatal(err)
		}
		c := datapath.GatewayConfig{PodIP: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 1320, Encryption: "wireguard", Clients: []netip.Addr{netip.MustParseAddr("10.42.1.8")}}
		if err := b.ApplyGateway(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		wg, err := wgctrl.New()
		if err != nil {
			t.Fatal(err)
		}
		defer wg.Close()
		d, err := wg.Device(datapath.WireGuardDevice)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Peers) != 0 {
			t.Fatal("gateway peer created before authenticated registration")
		}
		key1, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		key2, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		gw := netip.MustParseAddr("10.42.2.4")
		client1 := netip.MustParseAddr("10.42.1.8")
		client2 := netip.MustParseAddr("10.42.1.9")
		for _, peer := range []struct {
			ip  netip.Addr
			key string
		}{{client1, key1.PublicKey().String()}, {client2, key2.PublicKey().String()}, {client1, key1.PublicKey().String()}} {
			if err := b.RegisterPeer(context.Background(), gw, peer.ip, peer.key); err != nil {
				t.Fatal(err)
			}
		}
		d, err = wg.Device(datapath.WireGuardDevice)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Peers) != 2 {
			t.Fatalf("authenticated gateway peers duplicated or lost: %d", len(d.Peers))
		}
		link, err := b.h.LinkByName(datapath.WireGuardDevice)
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{"10.42.1.8", "10.42.1.9"} {
			r, err := netlink.RouteGetWithOptions(net.ParseIP(target), &netlink.RouteGetOptions{})
			if err != nil || len(r) != 1 || r[0].LinkIndex != link.Attrs().Index || !r[0].Src.Equal(net.ParseIP("10.42.2.4")) {
				t.Fatalf("gateway authenticated peer route/source invalid %s: %v %v", target, r, err)
			}
		}
		if err := b.UnregisterPeer(context.Background(), client1); err != nil {
			t.Fatal(err)
		}
		d, err = wg.Device(datapath.WireGuardDevice)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Peers) != 1 {
			t.Fatal("unregistered peer remained in kernel")
		}
		r, err := netlink.RouteGetWithOptions(net.ParseIP("10.42.1.8"), &netlink.RouteGetOptions{})
		if err != nil && len(r) != 0 {
			t.Fatal(err)
		}
		if err == nil && len(r) == 1 && r[0].LinkIndex == link.Attrs().Index {
			t.Fatal("removed peer still routed through WG")
		}
	})
}

func TestPrivilegedClearGatewayPeersAfterRestart(t *testing.T) {
	isolated(t, func(b *Backend) {
		eth := dummy(t, b, "eth0", "10.42.2.4/24")
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: net.ParseIP("10.42.2.1")}); err != nil {
			t.Fatal(err)
		}
		cfg := datapath.GatewayConfig{PodIP: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 1320, Encryption: "wireguard", Clients: []netip.Addr{netip.MustParseAddr("10.42.1.8"), netip.MustParseAddr("10.42.1.9")}}
		if err := b.ApplyGateway(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		publicBefore, err := b.WireGuardPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		mainBefore := mainRoutes(t, b)
		foreignDst := netip.MustParsePrefix("198.51.100.0/24")
		foreign := netlink.Route{Family: unix.AF_INET, Table: datapath.WireGuardTable, Dst: prefix(foreignDst), LinkIndex: eth.Attrs().Index, Scope: netlink.SCOPE_LINK, Protocol: 99}
		if err := b.h.RouteAdd(&foreign); err != nil {
			t.Fatal(err)
		}
		foreignRule := netlink.NewRule()
		foreignRule.Family = unix.AF_INET
		foreignRule.Priority = wgRoutePriority
		foreignRule.Protocol = 99
		foreignRule.Table = 200
		foreignRule.Dst = prefix(foreignDst)
		if err := b.h.RuleAdd(foreignRule); err != nil {
			t.Fatal(err)
		}
		for _, addr := range []string{"10.42.1.8", "10.42.1.9"} {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := b.RegisterPeer(context.Background(), cfg.PodIP, netip.MustParseAddr(addr), key.PublicKey().String()); err != nil {
				t.Fatal(err)
			}
		}
		wg, err := wgctrl.New()
		if err != nil {
			t.Fatal(err)
		}
		defer wg.Close()
		device, err := wg.Device(datapath.WireGuardDevice)
		if err != nil || len(device.Peers) != 2 {
			t.Fatalf("expected two previously authenticated peers: %v %v", device, err)
		}
		for i := 0; i < 2; i++ {
			if err := b.ClearGatewayPeers(context.Background()); err != nil {
				t.Fatal(err)
			}
			device, err = wg.Device(datapath.WireGuardDevice)
			if err != nil || len(device.Peers) != 0 {
				t.Fatalf("peer survived gateway restart reset %d: %v %v", i, device, err)
			}
			if got, err := b.WireGuardPublicKey(); err != nil || got != publicBefore {
				t.Fatalf("kernel gateway identity changed on reset: %v", err)
			}
		}
		routes, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: datapath.WireGuardTable}, netlink.RT_FILTER_TABLE)
		if err != nil {
			t.Fatal(err)
		}
		foundForeign, foundFallback := false, false
		for _, route := range routes {
			if route.Dst != nil && route.Dst.String() == foreignDst.String() && int(route.Protocol) == 99 {
				foundForeign = true
			}
			if route.Type == unix.RTN_UNREACHABLE && int(route.Protocol) == datapath.RouteProtocol {
				foundFallback = true
			}
			for _, addr := range []string{"10.42.1.8/32", "10.42.1.9/32"} {
				if route.Dst != nil && route.Dst.String() == addr && int(route.Protocol) == datapath.RouteProtocol {
					t.Fatalf("stale registered client route: %s", route.Dst)
				}
			}
		}
		if !foundForeign || !foundFallback {
			t.Fatal("reset removed foreign route or unreachable fallback")
		}
		rules, err := b.h.RuleList(unix.AF_INET)
		if err != nil {
			t.Fatal(err)
		}
		foundForeignRule, foundBypass := false, false
		for _, rule := range rules {
			if rule.Priority == wgRoutePriority && rule.Protocol == 99 && rule.Table == 200 && rule.Dst != nil && rule.Dst.String() == foreignDst.String() {
				foundForeignRule = true
			}
			if rule.Priority == wgBypassPriority && rule.Protocol == datapath.RouteProtocol && rule.Table == unix.RT_TABLE_MAIN {
				foundBypass = true
			}
			if rule.Priority == wgRoutePriority && rule.Protocol == datapath.RouteProtocol && rule.Table == datapath.WireGuardTable {
				t.Fatalf("stale peer lookup rule: %s", rule)
			}
		}
		if !foundForeignRule || !foundBypass {
			t.Fatal("reset removed foreign rule or transport bypass")
		}
		if !reflect.DeepEqual(mainBefore, mainRoutes(t, b)) {
			t.Fatal("reset modified gateway main routes")
		}
		if _, err := b.h.LinkByName(datapath.GatewayDevice); err != nil {
			t.Fatal("reset removed GENEVE link")
		}
	})
}
