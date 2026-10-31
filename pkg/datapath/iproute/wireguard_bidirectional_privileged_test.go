//go:build linux && privileged

package iproute

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// Three disposable netns prove a *real* selected client GENEVE request over
// WireGuard reaches upstream and its reply takes the LWT GENEVE return path.
func TestPrivilegedWireGuardBidirectionalReturn(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	gwNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := netns.Set(orig); e != nil {
			t.Error(e)
		}
		_ = gwNS.Close()
	}()
	gw, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	add := func(h *netlink.Handle, name, addr string) {
		t.Helper()
		l, e := h.LinkByName(name)
		if e != nil {
			t.Fatal(e)
		}
		if e = h.LinkSetUp(l); e != nil {
			t.Fatal(e)
		}
		a, e := netlink.ParseAddr(addr)
		if e != nil {
			t.Fatal(e)
		}
		if e = h.AddrAdd(l, a); e != nil {
			t.Fatal(e)
		}
	}
	if err = gw.h.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "eth0", MTU: 1500}, PeerName: "client-peer"}); err != nil {
		t.Fatal(err)
	}
	if err = gw.h.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: datapath.UpstreamDevice, MTU: 1500}, PeerName: "upstream-peer"}); err != nil {
		t.Fatal(err)
	}
	add(gw.h, "eth0", "10.42.2.4/24")
	add(gw.h, datapath.UpstreamDevice, "198.19.0.2/24")
	clientIP := netip.MustParseAddr("10.42.3.8")
	gatewayIP := netip.MustParseAddr("10.42.2.4")
	cfg := datapath.GatewayConfig{PodIP: gatewayIP, GatewayID: 7, MTU: 1320, Encryption: "wireguard", WireGuardPort: 51820, Clients: []netip.Addr{clientIP}, UpstreamHealthy: true}
	if err = gw.ApplyGateway(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	gwPub, err := gw.WireGuardPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := gw.h.LinkByName("client-peer")
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
	if err = netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	if err = gw.h.LinkSetNsFd(peer, int(clientNS)); err != nil {
		t.Fatal(err)
	}
	if err = netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	cl, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	eth, err := cl.h.LinkByName("client-peer")
	if err != nil {
		t.Fatal(err)
	}
	if err = cl.h.LinkSetName(eth, "eth0"); err != nil {
		t.Fatal(err)
	}
	add(cl.h, "eth0", "10.42.3.8/24")
	ce, err := cl.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	if err = cl.h.RouteAdd(&netlink.Route{LinkIndex: ce.Attrs().Index, Dst: host(gatewayIP), Scope: netlink.SCOPE_LINK}); err != nil {
		t.Fatal(err)
	}
	clientCfg := datapath.ClientConfig{PodIP: clientIP, Endpoint: gatewayIP, GatewayID: 7, MTU: 1320, Encryption: "wireguard", WireGuardPort: 51820, GatewayPublicKey: gwPub, RegistrationCACert: "fixture"}
	pub, err := cl.PrepareClientWireGuard(context.Background(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	ge, err := gw.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	if err = gw.h.RouteAdd(&netlink.Route{LinkIndex: ge.Attrs().Index, Dst: host(clientIP), Scope: netlink.SCOPE_LINK}); err != nil {
		t.Fatal(err)
	}
	if err = gw.RegisterPeer(context.Background(), gatewayIP, clientIP, pub); err != nil {
		t.Fatal(err)
	}
	if err = netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	if err = cl.ApplyClient(context.Background(), clientCfg); err != nil {
		t.Fatal(err)
	}
	upPeer, err := gw.h.LinkByName("upstream-peer")
	if err != nil {
		t.Fatal(err)
	}
	upstreamNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := netns.Set(orig); e != nil {
			t.Error(e)
		}
		_ = upstreamNS.Close()
	}()
	if err = netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	if err = gw.h.LinkSetNsFd(upPeer, int(upstreamNS)); err != nil {
		t.Fatal(err)
	}
	if err = netns.Set(upstreamNS); err != nil {
		t.Fatal(err)
	}
	uh, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer uh.Close()
	add(uh, "upstream-peer", "198.19.0.1/24")
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.19.0.1"), Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	_ = srv.SetDeadline(time.Now().Add(2 * time.Second))
	if err = netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(clientIP.String())})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.WriteToUDP([]byte("request"), &net.UDPAddr{IP: net.ParseIP("198.19.0.1"), Port: 8080}); err != nil {
		t.Fatal(err)
	}
	if err = netns.Set(upstreamNS); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, src, err := srv.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("request over authenticated WG not received: %v", err)
	}
	if string(buf[:n]) != "request" {
		t.Fatal("unexpected upstream request")
	}
	if _, err = srv.WriteToUDP([]byte("response"), src); err != nil {
		t.Fatal(err)
	}
	if err = netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	n, _, err = conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("response bypassed GENEVE return via WG: %v", err)
	}
	if string(buf[:n]) != "response" {
		t.Fatalf("response payload=%q", buf[:n])
	}
	if err = netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	gnv, err := gw.h.LinkByName(datapath.GatewayDevice)
	if err != nil {
		t.Fatal(err)
	}
	if gnv.Attrs().Statistics.RxPackets == 0 || gnv.Attrs().Statistics.TxPackets == 0 {
		t.Fatal(fmt.Sprintf("missing WG-carried bidirectional GENEVE: %+v", gnv.Attrs().Statistics))
	}
}
