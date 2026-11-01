//go:build linux && privileged

package observability

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
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
	// Send one real plaintext UDP6081 from this disposable gateway netns.
	// OUTPUT must drop and its exported kernel counter must advance.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.42.2.4")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteToUDP([]byte("plaintext-probe"), &net.UDPAddr{IP: net.ParseIP("10.42.2.4"), Port: datapath.GenevePort}); err != nil && !errors.Is(err, unix.EPERM) {
		t.Fatal(err)
	}
	_ = conn.Close()
	deadline := time.Now().Add(time.Second)
	for {
		text := guardScrape(t, guardHandler(func() ([]*nftables.Chain, map[string][]*nftables.Rule, map[string]uint64, error) {
			// The collector runs on another Go OS thread. Pin and enter this
			// disposable netns: production gateway workers already live there.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if e := netns.Set(target); e != nil {
				return nil, nil, nil, e
			}
			defer func() { _ = netns.Set(orig) }() // test-only worker restores its disposable namespace before unlocking.
			return KernelPlaintextGuard()
		}))
		if strings.Contains(text, "\nratatoskr_gateway_plaintext_geneve_drop_packets{direction=\"output\"} 1\n") {
			guardMetric(t, text, "sample_ok", "input", "1")
			guardMetric(t, text, "sample_ok", "output", "1")
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("plaintext OUTPUT guard kernel counter did not advance")
		}
		time.Sleep(10 * time.Millisecond)
	}
	guardMetric(t, first, "drop_packets", "output", "0")
}
