//go:build linux && privileged

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func TestPrivilegedGeneveAddressOwnership(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		eth, err := b.h.LinkByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}); err != nil {
			t.Fatal(err)
		}
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400, Endpoint: netip.MustParseAddr("10.42.2.4")}
		for i := 0; i < 2; i++ {
			if err := b.ApplyClient(context.Background(), c); err != nil {
				t.Fatal(err)
			}
		}
		check := func() {
			t.Helper()
			link, err := b.h.LinkByName(datapath.GatewayDevice)
			if err != nil {
				t.Fatal(err)
			}
			addrs, err := b.h.AddrList(link, unix.AF_INET)
			if err != nil {
				t.Fatal(err)
			}
			if len(addrs) != 1 || addrs[0].IPNet.String() != geneveClientAddress.String() {
				t.Fatalf("owned GENEVE addresses=%v", addrs)
			}
			if err := b.VerifyClient(context.Background(), c); err != nil {
				t.Fatalf("attached program did not verify owned address: %v", err)
			}
		}
		check()
		restarted, err := New()
		if err != nil {
			t.Fatal(err)
		}
		defer restarted.Close()
		if err := restarted.VerifyClient(context.Background(), c); err != nil {
			t.Fatalf("restart verifier rejected owned /32: %v", err)
		}
		c.Endpoint = netip.MustParseAddr("10.42.2.5")
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		check()
		link, err := b.h.LinkByName(datapath.GatewayDevice)
		if err != nil {
			t.Fatal(err)
		}
		foreign, err := netlink.ParseAddr("169.254.64.3/32")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.AddrAdd(link, foreign); err != nil {
			t.Fatal(err)
		}
		if err := b.ApplyClient(context.Background(), c); err == nil {
			t.Fatal("foreign address on GENEVE accepted")
		}
		if err := restarted.VerifyClient(context.Background(), c); err == nil {
			t.Fatal("foreign address passed restart verification")
		}
		addrs, err := b.h.AddrList(link, unix.AF_INET)
		if err != nil {
			t.Fatal(err)
		}
		if len(addrs) != 2 {
			t.Fatal("foreign address was modified")
		}
		if err := b.h.AddrDel(link, foreign); err != nil {
			t.Fatal(err)
		}
		if err := b.RemoveClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if _, err := b.h.LinkByName(datapath.GatewayDevice); err == nil {
			t.Fatal("RemoveClient left owned address/device")
		}
	})
}
func TestPrivilegedUnhealthyGeneveAddressLifecycle(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		eth, err := b.h.LinkByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}); err != nil {
			t.Fatal(err)
		}
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400, Endpoint: netip.MustParseAddr("10.42.2.4")}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		c.Endpoint = netip.Addr{}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if _, err := b.h.LinkByName(datapath.GatewayDevice); err == nil {
			t.Fatal("no-endpoint state left GENEVE link/address")
		}
		if err := b.VerifyClient(context.Background(), c); err != nil {
			t.Fatalf("no-endpoint attached policy failed verification: %v", err)
		}
		c.Endpoint = netip.MustParseAddr("10.42.2.5")
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		link, err := b.h.LinkByName(datapath.GatewayDevice)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.verifyGeneveAddress(link); err != nil {
			t.Fatal(err)
		}
	})
}
