//go:build linux && privileged

package observability

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Reads actual typed nftables expressions after production ApplyGateway in a
// disposable namespace. No cluster or host namespace nftables are queried.
func TestPrivilegedGatewayPlaintextGuardRealKernel(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	target, err := netns.New()
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("no disposable netns capability")
		}
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(orig); err != nil {
			t.Error(err)
		}
		_ = target.Close()
	}()
	backend, err := iproute.New()
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	eth := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", MTU: 1500}}
	if err := netlink.LinkAdd(eth); err != nil {
		t.Fatal(err)
	}
	a, err := netlink.ParseAddr("10.42.2.4/24")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.AddrAdd(eth, a); err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(eth); err != nil {
		t.Fatal(err)
	}
	cfg := datapath.GatewayConfig{PodIP: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 1320, Encryption: "wireguard", WireGuardPort: 51820}
	if err = backend.ApplyGateway(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	chains, rules, raw, err := KernelPlaintextGuard()
	if err != nil {
		t.Fatal(err)
	}
	collector := NewGatewayPlaintextGuard(func() ([]*nftables.Chain, map[string][]*nftables.Rule, map[string]uint64, error) {
		return chains, rules, raw, nil
	})
	first := guardScrape(t, guardHandler(collector.read))
	guardMetric(t, first, "sample_ok", "input", "1")
	guardMetric(t, first, "sample_ok", "output", "1")
	guardMetric(t, first, "drop_packets", "input", "0")
	guardMetric(t, first, "drop_packets", "output", "0")
}
