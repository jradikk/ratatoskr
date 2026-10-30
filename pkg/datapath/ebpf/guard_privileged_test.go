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

func TestPrivilegedUpdateGuardLifecycle(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		eth, err := b.h.LinkByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}); err != nil {
			t.Fatal(err)
		}
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), Endpoint: netip.MustParseAddr("10.42.1.9"), GatewayID: 7, MTU: 1400}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if guard, err := b.findUpdateGuard(eth); err != nil || guard != nil {
			t.Fatalf("successful initial apply retained guard: %v %v", guard, err)
		}
		restarted, err := New()
		if err != nil {
			t.Fatal(err)
		}
		defer restarted.Close()
		c.Endpoint = netip.MustParseAddr("10.42.1.10")
		if err := restarted.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if guard, err := restarted.findUpdateGuard(eth); err != nil || guard != nil {
			t.Fatalf("successful restart update retained guard: %v %v", guard, err)
		}
		if err := restarted.VerifyClient(context.Background(), c); err != nil {
			t.Fatalf("restart update not verified: %v", err)
		}
		// An interrupted update retains its deny-all guard, and a later Apply
		// must recover without deleting foreign filters or needing program-by-ID.
		if err := restarted.installUpdateGuard(eth); err != nil {
			t.Fatal(err)
		}
		if err := restarted.VerifyClient(context.Background(), c); err == nil {
			t.Fatal("restart adopted incomplete guarded update")
		}
		if err := restarted.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if guard, err := restarted.findUpdateGuard(eth); err != nil || guard != nil {
			t.Fatalf("recovery retained guard: %v %v", guard, err)
		}
		malformed := c
		malformed.Policy.Mode = "invalid"
		if err := restarted.ApplyClient(context.Background(), malformed); err == nil {
			t.Fatal("invalid update accepted")
		}
		if guard, err := restarted.findUpdateGuard(eth); err != nil || guard == nil {
			t.Fatalf("invalid update left prior selector exposed: %v", err)
		}
		if err := restarted.VerifyClient(context.Background(), c); err == nil {
			t.Fatal("guarded invalid update was adopted")
		}
		if err := restarted.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if guard, err := restarted.findUpdateGuard(eth); err != nil || guard != nil {
			t.Fatalf("malformed policy recovery retained guard: %v", err)
		}
		foreign := &netlink.MatchAll{FilterAttrs: netlink.FilterAttrs{LinkIndex: eth.Attrs().Index, Parent: netlink.HANDLE_MIN_EGRESS, Priority: guardPriority, Protocol: unix.ETH_P_ALL}, Actions: []netlink.Action{&netlink.GenericAction{ActionAttrs: netlink.ActionAttrs{Action: netlink.TC_ACT_OK}}}}
		if err := b.h.FilterAdd(foreign); err != nil {
			t.Fatal(err)
		}
		if err := restarted.ApplyClient(context.Background(), c); err == nil {
			t.Fatal("foreign priority-419 filter accepted as owned guard")
		}
		filters, err := b.h.FilterList(eth, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range filters {
			if f.Attrs().Priority == guardPriority {
				found = true
				if isOwnedUpdateGuard(f) {
					t.Fatal("foreign guard was modified")
				}
			}
		}
		if !found {
			t.Fatal("foreign guard removed")
		}
		if err := b.h.FilterDel(foreign); err != nil {
			t.Fatal(err)
		}
		if err := restarted.RemoveClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		filters, err = b.h.FilterList(eth, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range filters {
			if f.Attrs().Priority == guardPriority || f.Attrs().Priority == filterPriority {
				t.Fatalf("explicit removal left Ratatoskr tc state: %v", f)
			}
		}
	})
}
