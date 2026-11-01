//go:build linux && privileged

package iproute

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// The metadata address exists ONLY on a disposable sibling netns. The test
// sends real packets over a veth, never to a host/cloud metadata endpoint.
func TestPrivilegedMetadataPacketProhibition(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	clientNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(orig); err != nil {
			t.Errorf("restore original namespace: %v", err)
		}
		_ = clientNS.Close()
	}()
	peerNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer peerNS.Close()
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { b.Close() }()
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "eth0", MTU: 1500}, PeerName: "peer0"}
	if err := b.h.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	eth, err := b.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.h.LinkSetNsFd(eth, int(clientNS)); err != nil {
		t.Fatal(err)
	}
	peer, err := b.h.LinkByName("peer0")
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"10.42.1.1/24", "169.254.169.254/32", "10.96.0.10/32", "10.96.0.1/32"} {
		a, parseErr := netlink.ParseAddr(address)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if err := b.h.AddrAdd(peer, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.h.LinkSetUp(peer); err != nil {
		t.Fatal(err)
	}
	metadataUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("169.254.169.254"), Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	defer metadataUDP.Close()
	metadataTCP, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("169.254.169.254"), Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	defer metadataTCP.Close()
	dnsUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.96.0.10"), Port: 5353})
	if err != nil {
		t.Fatal(err)
	}
	defer dnsUDP.Close()
	apiTCP, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("10.96.0.1"), Port: 8443})
	if err != nil {
		t.Fatal(err)
	}
	defer apiTCP.Close()
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	b.Close()
	b, err = New()
	if err != nil {
		t.Fatal(err)
	}
	eth, err = b.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	addr, err := netlink.ParseAddr("10.42.1.8/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.h.AddrAdd(eth, addr); err != nil {
		t.Fatal(err)
	}
	if err := b.h.LinkSetUp(eth); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"169.254.169.254/32", "10.96.0.0/16"} {
		dst, parseErr := netlink.ParseIPNet(destination)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: dst, Gw: net.ParseIP("10.42.1.1")}); err != nil {
			t.Fatal(err)
		}
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.42.1.8")})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()

	probeUDP := func(name string, listener *net.UDPConn, dst *net.UDPAddr, allowed bool) {
		t.Helper()
		_, writeErr := udp.WriteToUDP([]byte("owned-probe"), dst)
		if err := listener.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, _, readErr := listener.ReadFromUDP(buf)
		if allowed {
			if writeErr != nil || readErr != nil || string(buf[:n]) != "owned-probe" {
				t.Fatalf("%s direct UDP unavailable: write=%v read=%v payload=%q", name, writeErr, readErr, buf[:n])
			}
		} else {
			var timeout net.Error
			if !errors.As(readErr, &timeout) || !timeout.Timeout() {
				t.Fatalf("%s leaked UDP to sibling: write=%v read=%v payload=%q", name, writeErr, readErr, buf[:n])
			}
		}
	}
	probeTCP := func(name string, listener *net.TCPListener, dst string, allowed bool) {
		t.Helper()
		conn, dialErr := net.DialTimeout("tcp4", dst, 300*time.Millisecond)
		if conn != nil {
			defer conn.Close()
		}
		if allowed && dialErr != nil {
			t.Fatalf("%s direct TCP unavailable: %v", name, dialErr)
		}
		if !allowed && (!errors.Is(dialErr, unix.EACCES) && !errors.Is(dialErr, unix.ENETUNREACH) && !errors.Is(dialErr, unix.EHOSTUNREACH)) {
			t.Fatalf("%s must fail locally as prohibited/unreachable, got %v", name, dialErr)
		}
		if err := listener.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		accepted, acceptErr := listener.AcceptTCP()
		if accepted != nil {
			defer accepted.Close()
		}
		if allowed {
			if acceptErr != nil {
				t.Fatalf("%s direct TCP not delivered: %v", name, acceptErr)
			}
		} else {
			var timeout net.Error
			if !errors.As(acceptErr, &timeout) || !timeout.Timeout() {
				t.Fatalf("%s leaked TCP to sibling: %v", name, acceptErr)
			}
		}
	}
	metadataDst := &net.UDPAddr{IP: net.ParseIP("169.254.169.254"), Port: 8080}
	dnsDst := &net.UDPAddr{IP: net.ParseIP("10.96.0.10"), Port: 5353}
	probeDirect := func() {
		t.Helper()
		probeUDP("cluster DNS", dnsUDP, dnsDst, true)
		probeTCP("cluster API", apiTCP, "10.96.0.1:8443", true)
	}
	// First prove the disposable endpoints actually receive packets before
	// attributing missing packets to a policy rule.
	probeDirect()
	probeUDP("metadata baseline", metadataUDP, metadataDst, true)
	probeTCP("metadata baseline", metadataTCP, "169.254.169.254:8080", true)

	cfg := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400,
		Endpoint:   netip.MustParseAddr("10.42.2.4"),
		Exclusions: []netip.Prefix{netip.MustParsePrefix("10.96.0.0/16")},
		Policy:     datapath.Policy{Mode: "include", Rules: []datapath.Rule{{CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, Ports: []datapath.Port{{Protocol: "TCP", Port: 8080}}}}}}
	for _, mode := range []string{"include", ""} {
		t.Logf("checking metadata prohibition in policy mode %q", mode)
		cfg.Policy.Mode = mode
		if mode == "" {
			cfg.Policy.Rules = nil
		}
		if err := b.ApplyClient(context.Background(), cfg); err != nil {
			t.Fatalf("%q closed policy: %v", mode, err)
		}
		probeDirect() // Cluster exclusions remain usable even in full-tunnel mode.
		probeUDP("metadata prohibited "+mode, metadataUDP, metadataDst, false)
		probeTCP("metadata prohibited "+mode, metadataTCP, "169.254.169.254:8080", false)
	}
	// Explicit AllowCloudMetadata changes only the metadata bypass; it does
	// not grant the workload permission to change the authorized config.
	cfg.AllowCloudMetadata = true
	if err := b.ApplyClient(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	probeDirect()
	probeUDP("explicit metadata bypass", metadataUDP, metadataDst, true)
	probeTCP("explicit metadata bypass", metadataTCP, "169.254.169.254:8080", true)
}
