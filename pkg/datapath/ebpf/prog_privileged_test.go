//go:build linux && privileged

package ebpf

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func isolated(t *testing.T, fn func(*Backend)) {
	t.Helper()
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
			t.Error(err)
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
func dummy(t *testing.T, b *Backend) {
	t.Helper()
	l := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", MTU: 1500}}
	if err := b.h.LinkAdd(l); err != nil {
		t.Fatal(err)
	}
	link, err := b.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.h.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	a, err := netlink.ParseAddr("10.42.1.8/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.h.AddrAdd(link, a); err != nil {
		t.Fatal(err)
	}
}
func packet(dst string, port uint16, ipv6 bool) []byte {
	out := make([]byte, 14+20+8)
	out[12] = 0x08
	out[13] = 0
	if ipv6 {
		out[12] = 0x86
		out[13] = 0xdd
		return out
	}
	out[14] = 0x45
	out[23] = 17
	copy(out[26:30], net.ParseIP("10.42.1.8").To4())
	copy(out[30:34], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(out[36:38], port)
	return out
}
func TestPrivilegedTestRunPolicy(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400, Endpoint: netip.Addr{}, Exclusions: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}}
		check := func(name string, c datapath.ClientConfig, want map[string]uint32) {
			t.Helper()
			if err := b.ApplyClient(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			for dst, verdict := range want {
				got, _, err := b.objects.Steer.Test(packet(dst, 443, false))
				if err != nil {
					t.Fatalf("%s %s: %v", name, dst, err)
				}
				if got != verdict {
					t.Fatalf("%s %s: action=%d, want %d", name, dst, got, verdict)
				}
			}
		}
		check("full", c, map[string]uint32{"203.0.113.7": 2, "10.42.1.11": 0, "169.254.64.1": 0, "169.254.169.254": 2})
		c.Policy = datapath.Policy{Mode: "include", Rules: []datapath.Rule{{CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Ports: []datapath.Port{{Protocol: "UDP", Port: 443}}}}}
		check("include", c, map[string]uint32{"203.0.113.7": 2, "198.51.100.7": 0, "10.42.1.11": 0})
		got, _, err := b.objects.Steer.Test(packet("203.0.113.7", 80, false))
		if err != nil || got != 0 {
			t.Fatalf("non-selected UDP port was steered: %d %v", got, err)
		}
		c.Policy.Mode = "exclude"
		check("exclude", c, map[string]uint32{"203.0.113.7": 0, "198.51.100.7": 2, "10.42.1.11": 0})
		got, _, err = b.objects.Steer.Test(packet("203.0.113.7", 80, false))
		if err != nil || got != 2 {
			t.Fatalf("non-excluded UDP port leaked: %d %v", got, err)
		}
		// Program.Test rejects a malformed 14-byte IPv6 fixture before invoking
		// tc; the live clsact hook is responsible for unsupported IPv6 drops.
		if err := b.RemoveClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	})
}
func TestPrivilegedEndpointMetadata(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400, Endpoint: netip.MustParseAddr("10.42.2.4")}
		eth, err := b.h.LinkByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}); err != nil {
			t.Fatal(err)
		}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if c, err := b.h.LinkByName(datapath.GatewayDevice); err != nil {
			t.Fatal(err)
		} else if g, ok := c.(*netlink.Geneve); !ok || !g.FlowBased || g.Dport != datapath.GenevePort {
			t.Fatalf("missing collect_md Geneve: %v", c)
		}
		cfg := clientClientConfig{}
		if err := b.objects.Config.Lookup(uint32(0), &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Endpoint != binary.BigEndian.Uint32(c.Endpoint.AsSlice()) || cfg.PodIp != addrU32(c.PodIP) || cfg.GatewayId != 7 || cfg.Ifindex == 0 || cfg.Healthy != 1 {
			t.Fatalf("tunnel metadata not provisioned: %+v", cfg)
		}
		opt := clientGeneveOpt{}
		if err := b.objects.Identity.Lookup(uint32(0), &opt); err != nil {
			t.Fatal(err)
		}
		if opt.Type != 1 || opt.Len != 2 {
			t.Fatal("Geneve identity TLV metadata missing")
		}
		dst := clientLpmV4{Prefixlen: 32, Addr: addrU32(c.Endpoint)}
		var included uint8
		if err := b.objects.ExcludeV4.Lookup(dst, &included); err != nil || included != 1 {
			t.Fatalf("gateway endpoint not excluded from recursive steering: %v", err)
		}
		if err := b.RemoveClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if _, err := b.h.LinkByName(datapath.GatewayDevice); err == nil {
			t.Fatal("Geneve device survived explicit removal")
		}
	})
}

// A packet traverses tc eth0 egress into collect_md GENEVE, then returns via
// the same namespace's loopback pod network; this is not a cluster e2e suite.
func TestPrivilegedGeneveTCAction(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400, Endpoint: netip.MustParseAddr("10.42.1.9")}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		eth, err := b.h.LinkByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}); err != nil {
			t.Fatal(err)
		}
		geneve, err := b.h.LinkByName(datapath.GatewayDevice)
		if err != nil {
			t.Fatal(err)
		}
		before := geneve.Attrs().Statistics.TxPackets
		if _, err := b.h.RouteGet(net.ParseIP("10.42.1.9")); err != nil {
			t.Fatal(err)
		}
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.42.1.8")})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.WriteToUDP([]byte("m6-healthy-geneve"), &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}); err != nil {
			t.Fatal(err)
		}
		geneve, err = b.h.LinkByName(datapath.GatewayDevice)
		if err != nil {
			t.Fatal(err)
		}
		if geneve.Attrs().Statistics.TxPackets <= before {
			t.Fatal("healthy flow never entered external GENEVE device from tc egress")
		}
		filters, err := b.h.FilterList(eth, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range filters {
			if f.Attrs().Priority == filterPriority && f.Attrs().Handle == filterHandle {
				found = true
			}
		}
		if !found {
			t.Fatal("tc egress filter missing")
		}
	})
}

// A local socket with an ordinary eth0 default must be dropped by tc when
// its destination is selected but no endpoint is healthy.
func TestPrivilegedNoEndpointDropsLocalUDP(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		eth, err := b.h.LinkByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}); err != nil {
			t.Fatal(err)
		}
		sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.42.1.8")})
		if err != nil {
			t.Fatal(err)
		}
		defer sock.Close()
		for i := 0; i < 2; i++ {
			if _, err := sock.WriteToUDP([]byte("must-drop"), &net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 443}); err != nil {
				t.Fatal(err)
			}
		}
		reason := uint32(0)
		var counters []uint64
		if err := b.objects.Stats.Lookup(&reason, &counters); err != nil {
			t.Fatal(err)
		}
		var dropped uint64
		for _, n := range counters {
			dropped += n
		}
		if dropped < 2 {
			t.Fatalf("selected local packets without endpoint were not dropped, count=%d", dropped)
		}
		if err := b.RemoveClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPrivilegedRefuseWrongOuterSource(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		eth, err := b.h.LinkByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		other, err := netlink.ParseAddr("10.42.1.9/24")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.AddrAdd(eth, other); err != nil {
			t.Fatal(err)
		}
		target, err := netlink.ParseAddr("203.0.113.7/32")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: target.IPNet, Src: net.ParseIP("10.42.1.9")}); err != nil {
			t.Fatal(err)
		}
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400, Endpoint: netip.MustParseAddr("203.0.113.7")}
		if err := b.ApplyClient(context.Background(), c); err == nil {
			t.Fatal("accepted Geneve underlay outer source different from client pod IP")
		}
		if _, err := b.h.LinkByName(datapath.GatewayDevice); err == nil {
			t.Fatal("unsafe source configuration created Geneve device")
		}
	})
}

func TestPrivilegedEarlierPassBypassesNoEndpointDrop(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		eth, err := b.h.LinkByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		q := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: eth.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}}
		if err := b.h.QdiscAdd(q); err != nil {
			t.Fatal(err)
		}
		foreign := &netlink.MatchAll{FilterAttrs: netlink.FilterAttrs{LinkIndex: eth.Attrs().Index, Parent: netlink.HANDLE_MIN_EGRESS, Priority: 100, Protocol: unix.ETH_P_ALL}, Actions: []netlink.Action{&netlink.GenericAction{ActionAttrs: netlink.ActionAttrs{Action: netlink.TC_ACT_OK}}}}
		if err := b.h.FilterAdd(foreign); err != nil {
			t.Fatal(err)
		}
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400}
		if err := b.ApplyClient(context.Background(), c); err == nil {
			t.Fatal("unsafe earlier clsact egress action bypassed Ratatoskr no-endpoint drop")
		}
		// Preserve foreign filter and refuse before installing our own program.
		filters, err := b.h.FilterList(eth, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			t.Fatal(err)
		}
		foundForeign, foundRatatoskr := false, false
		for _, f := range filters {
			if f.Attrs().Priority == 100 {
				foundForeign = true
			}
			if f.Attrs().Priority == filterPriority {
				foundRatatoskr = true
			}
		}
		if !foundForeign || foundRatatoskr {
			t.Fatalf("unexpected tc mutation: foreign=%t ratatoskr=%t", foundForeign, foundRatatoskr)
		}
	})
}

func TestPrivilegedVerifyAttachedProgramAndPolicyAfterRestart(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400, Exclusions: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}, Policy: datapath.Policy{Mode: "include", Rules: []datapath.Rule{{CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Ports: []datapath.Port{{Protocol: "UDP", Port: 443}}}}}}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if err := b.VerifyClient(context.Background(), c); err != nil {
			t.Fatalf("healthy attached tc verification failed: %v", err)
		}
		restarted, err := New()
		if err != nil {
			t.Fatal(err)
		}
		defer restarted.Close()
		if err := restarted.VerifyClient(context.Background(), c); err != nil {
			t.Fatalf("restarted backend failed to verify tc program/maps: %v", err)
		}
		modified := c
		modified.Policy.Mode = "exclude"
		if err := restarted.VerifyClient(context.Background(), modified); err == nil {
			t.Fatal("policy mismatch accepted on restart")
		}
		c.Endpoint = netip.Addr{}
		if err := restarted.VerifyClient(context.Background(), c); err != nil {
			t.Fatalf("no endpoint policy verification failed: %v", err)
		}
		if err := b.objects.Config.Put(uint32(0), clientClientConfig{}); err != nil {
			t.Fatal(err)
		}
		if err := restarted.VerifyClient(context.Background(), c); err == nil {
			t.Fatal("tampered tc config accepted")
		}
	})
}

func TestPrivilegedFailedEndpointUpdateRevokesOldKernelSelector(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		eth, err := b.h.LinkByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}); err != nil {
			t.Fatal(err)
		}
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400, Endpoint: netip.MustParseAddr("10.42.1.9")}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		changed := c
		changed.Endpoint = netip.MustParseAddr("198.18.0.8")
		// Force a failure *after* revocation by causing the next GENEVE lookup to
		// see an unrelated non-GENEVE device with the reserved name.
		if dev, err := b.h.LinkByName(datapath.GatewayDevice); err == nil {
			if err := b.h.LinkDel(dev); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Fatal(err)
		}
		fake := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: datapath.GatewayDevice}}
		if err := b.h.LinkAdd(fake); err != nil {
			t.Fatal(err)
		}
		if err := b.ApplyClient(context.Background(), changed); err == nil {
			t.Fatal("unexpectedly accepted bad GENEVE device")
		}
		config := clientClientConfig{}
		if err := b.objects.Config.Lookup(uint32(0), &config); err != nil {
			t.Fatal(err)
		}
		if config.Healthy != 0 || config.Endpoint != 0 || config.Ifindex != 0 {
			t.Fatalf("failed update left old healthy selector: %+v", config)
		}
		if err := b.VerifyClient(context.Background(), c); err == nil {
			t.Fatal("restart verifier accepted revoked old selector")
		}
	})
}
