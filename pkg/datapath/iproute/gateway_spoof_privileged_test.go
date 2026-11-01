//go:build linux && privileged

package iproute

import (
	"context"
	"encoding/binary"
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

// Packet-level verifier regression in two throwaway namespaces. Tests actual
// GENEVE decapsulation, not only installed flower attributes or filter lists.
func TestPrivilegedGatewayGeneveSpoofPackets(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	gatewayNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := netns.Set(orig); e != nil {
			t.Error(e)
		}
		_ = gatewayNS.Close()
	}()
	gateway, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	if err = gateway.h.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "eth0", MTU: 1500}, PeerName: "client-peer"}); err != nil {
		t.Fatal(err)
	}
	clientIP := netip.MustParseAddr("10.42.2.8")
	gatewayIP := netip.MustParseAddr("10.42.2.4")
	link, err := gateway.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	add := func(h *netlink.Handle, l netlink.Link, cidr string) {
		t.Helper()
		addr, e := netlink.ParseAddr(cidr)
		if e != nil {
			t.Fatal(e)
		}
		if e = h.AddrAdd(l, addr); e != nil {
			t.Fatal(e)
		}
		if e = h.LinkSetUp(l); e != nil {
			t.Fatal(e)
		}
	}
	add(gateway.h, link, "10.42.2.4/24")
	cfg := datapath.GatewayConfig{PodIP: gatewayIP, GatewayID: 7, MTU: 1320, Clients: []netip.Addr{clientIP}, UpstreamHealthy: false}
	if err = gateway.ApplyGateway(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	gnv, err := gateway.h.LinkByName(datapath.GatewayDevice)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := gateway.h.LinkByName("client-peer")
	if err != nil {
		t.Fatal(err)
	}
	clientNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := netns.Set(orig); e != nil {
			t.Error(e)
		}
		_ = clientNS.Close()
	}()
	if err = gateway.h.LinkSetNsFd(peer, int(clientNS)); err != nil {
		t.Fatal(err)
	}
	if err = netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	client, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	cl, err := client.h.LinkByName("client-peer")
	if err != nil {
		t.Fatal(err)
	}
	if err = client.h.LinkSetName(cl, "eth0"); err != nil {
		t.Fatal(err)
	}
	cl, err = client.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	add(client.h, cl, "10.42.2.8/24")
	// The second outer source is a deliberately forged PodIP, not a second
	// allowlisted peer; both sockets originate in the same disposable netns.
	foreign, err := netlink.ParseAddr("10.42.2.9/32")
	if err != nil {
		t.Fatal(err)
	}
	if err = client.h.AddrAdd(cl, foreign); err != nil {
		t.Fatal(err)
	}
	// Observe real outer UDP6081 arrival at gateway eth0 for each case,
	// independently of the GENEVE tc action. AF_PACKET sees only this test veth.
	if err = netns.Set(gatewayNS); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK, int((unix.ETH_P_ALL<<8)|(unix.ETH_P_ALL>>8)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: link.Attrs().Index, Protocol: uint16((unix.ETH_P_ALL << 8) | (unix.ETH_P_ALL >> 8))}); err != nil {
		t.Fatal(err)
	}
	// Minimal TEB GENEVE packet: inner Ethernet + IPv4 source injected below.
	payload := []byte{0, 0, 0x65, 0x58, 0, 0, 7, 0, 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 3, 0x08, 0,
		0x45, 0, 0, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 10, 42, 2, 8, 10, 42, 2, 4, 0, 0, 0, 0, 0, 0, 0, 0}
	send := func(source string, vni byte, inner byte) {
		t.Helper()
		if err = netns.Set(clientNS); err != nil {
			t.Fatal(err)
		}
		p := append([]byte(nil), payload...)
		p[6] = vni
		p[37] = inner
		c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(source)})
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		if _, e = c.WriteToUDP(p, &net.UDPAddr{IP: net.ParseIP(gatewayIP.String()), Port: datapath.GenevePort}); e != nil {
			t.Fatal(e)
		}
		if err = netns.Set(gatewayNS); err != nil {
			t.Fatal(err)
		}
		frame := make([]byte, 256)
		seen := false
		until := time.Now().Add(2 * time.Second)
		for time.Now().Before(until) {
			n, _, e := unix.Recvfrom(fd, frame, 0)
			if errors.Is(e, unix.EAGAIN) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if e != nil {
				t.Fatal(e)
			}
			if n >= 50 && binary.BigEndian.Uint16(frame[12:14]) == unix.ETH_P_IP && frame[23] == unix.IPPROTO_UDP &&
				net.IP(frame[26:30]).Equal(net.ParseIP(source)) && net.IP(frame[30:34]).Equal(net.ParseIP(gatewayIP.String())) &&
				binary.BigEndian.Uint16(frame[36:38]) == datapath.GenevePort && frame[46] == 0 && frame[47] == 0 && frame[48] == vni {
				seen = true
				break
			}
		}
		if !seen {
			t.Fatal("outer GENEVE packet not observed at gateway eth0")
		}
	}
	stats := func() (uint32, uint32) {
		t.Helper()
		if err = netns.Set(gatewayNS); err != nil {
			t.Fatal(err)
		}
		fs, e := gateway.h.FilterList(gnv, netlink.MakeHandle(0xffff, 0))
		if e != nil {
			t.Fatal(e)
		}
		var accept, drop uint32
		for _, f := range fs {
			switch filter := f.(type) {
			case *netlink.Flower:
				for _, a := range filter.Actions {
					if v := a.Attrs().Statistics; v != nil && v.Basic != nil {
						accept += v.Basic.Packets
					}
				}
			case *netlink.MatchAll:
				for _, a := range filter.Actions {
					if v := a.Attrs().Statistics; v != nil && v.Basic != nil {
						drop += v.Basic.Packets
					}
				}
			}
		}
		return accept, drop
	}
	wait := func(beforeAccept, beforeDrop uint32, positive bool) {
		t.Helper()
		until := time.Now().Add(2 * time.Second)
		for {
			gotAccept, gotDrop := stats()
			if positive {
				if gotAccept > beforeAccept && gotDrop == beforeDrop {
					return
				}
			} else if gotDrop > beforeDrop && gotAccept == beforeAccept {
				return
			}
			if time.Now().After(until) {
				t.Fatalf("flower verifier stage positive=%t accepted %d→%d dropped %d→%d", positive, beforeAccept, gotAccept, beforeDrop, gotDrop)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Known authorized positive is mandatory before any negative can qualify.
	good, bad := stats()
	send(clientIP.String(), 7, 8)
	wait(good, bad, true)
	for _, tc := range []struct {
		name, outer string
		vni, inner  byte
	}{
		{"outer source", "10.42.2.9", 7, 8},
		{"inner source", "10.42.2.8", 7, 9},
		{"VNI", "10.42.2.8", 8, 8},
	} {
		t.Run(tc.name, func(t *testing.T) { a, d := stats(); send(tc.outer, tc.vni, tc.inner); wait(a, d, false) })
	}
	if err = netns.Set(gatewayNS); err != nil {
		t.Fatal(err)
	}
	filters, err := gateway.h.FilterList(gnv, netlink.MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 2 {
		t.Fatalf("verifier filters changed: %d", len(filters))
	}
}
