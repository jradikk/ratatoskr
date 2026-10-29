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
		if len(rs) != 4 {
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
