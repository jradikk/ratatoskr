//go:build linux && privileged

package iproute

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// A disposable three-netns component: client GENEVE -> gateway -> upstream
// response -> gateway return GENEVE. No cluster or production network changes.
func TestPrivilegedGatewayBidirectionalReturn(t *testing.T) {
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
		if err := netns.Set(orig); err != nil {
			t.Error(err)
		}
		_ = gwNS.Close()
	}()
	gw, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	clientPair := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "eth0", MTU: 1500}, PeerName: "client-peer"}
	if err := gw.h.LinkAdd(clientPair); err != nil {
		t.Fatal(err)
	}
	upstreamPair := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: datapath.UpstreamDevice, MTU: 1500}, PeerName: "upstream-peer"}
	if err := gw.h.LinkAdd(upstreamPair); err != nil {
		t.Fatal(err)
	}
	add := func(h *netlink.Handle, name, addr string) {
		t.Helper()
		l, err := h.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
		a, err := netlink.ParseAddr(addr)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.AddrAdd(l, a); err != nil {
			t.Fatal(err)
		}
	}
	add(gw.h, "eth0", "10.42.2.4/24")
	add(gw.h, datapath.UpstreamDevice, "198.19.0.2/24")
	clientIP := netip.MustParseAddr("10.42.3.8")
	cfg := datapath.GatewayConfig{PodIP: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, Clients: []netip.Addr{clientIP}, MTU: 1400, UpstreamHealthy: true}
	if err := gw.ApplyGateway(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	underlay, err := gw.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	captureFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int((unix.ETH_P_ALL<<8)|(unix.ETH_P_ALL>>8)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(captureFD)
	if err := unix.Bind(captureFD, &unix.SockaddrLinklayer{Protocol: uint16((unix.ETH_P_ALL << 8) | (unix.ETH_P_ALL >> 8)), Ifindex: underlay.Attrs().Index}); err != nil {
		t.Fatal(err)
	}
	cPeer, err := gw.h.LinkByName("client-peer")
	if err != nil {
		t.Fatal(err)
	}
	clientNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(orig); err != nil {
			t.Error(err)
		}
		_ = clientNS.Close()
	}()
	if err := netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	if err := gw.h.LinkSetNsFd(cPeer, int(clientNS)); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	cl, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ce, err := cl.h.LinkByName("client-peer")
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.h.LinkSetName(ce, "eth0"); err != nil {
		t.Fatal(err)
	}
	add(cl.h, "eth0", "10.42.3.8/24")
	// Simulate flannel's cross-node pod subnets: each pod reaches the other
	// through a normal main-table CNI route; do not rely on a shared /24.
	clEth, err := cl.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.h.RouteAdd(&netlink.Route{LinkIndex: clEth.Attrs().Index, Dst: host(cfg.PodIP), Scope: netlink.SCOPE_LINK}); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	gwEth, err := gw.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	if err := gw.h.RouteAdd(&netlink.Route{LinkIndex: gwEth.Attrs().Index, Dst: host(clientIP), Scope: netlink.SCOPE_LINK}); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	cc := datapath.ClientConfig{PodIP: clientIP, Endpoint: cfg.PodIP, GatewayID: cfg.GatewayID, MTU: 1400}
	if err := cl.ApplyClient(context.Background(), cc); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(gwNS); err != nil {
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
		if err := netns.Set(orig); err != nil {
			t.Error(err)
		}
		_ = upstreamNS.Close()
	}()
	if err := netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	if err := gw.h.LinkSetNsFd(upPeer, int(upstreamNS)); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(upstreamNS); err != nil {
		t.Fatal(err)
	}
	uh, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer uh.Close()
	add(uh, "upstream-peer", "198.19.0.1/24")
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.19.0.1"), Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(clientIP.String())})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.WriteToUDP([]byte("request"), &net.UDPAddr{IP: net.ParseIP("198.19.0.1"), Port: 8080}); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(upstreamNS); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, src, err := upstream.ReadFromUDP(buf)
	if err != nil {
		showGatewayCounters(t, gw, gwNS)
		t.Fatalf("client request did not reach upstream: %v", err)
	}
	t.Logf("upstream received src=%s payload=%s", src, string(buf[:n]))
	if _, err := upstream.WriteToUDP([]byte("response"), src); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	n, src, err = client.ReadFromUDP(buf)
	if err != nil {
		showGatewayCounters(t, gw, gwNS)
		t.Fatalf("gateway return path failed: %v", err)
	}
	if string(buf[:n]) != "response" {
		t.Fatalf("response=%q from %s", buf[:n], src)
	}
	t.Logf("client received src=%s payload=%s", src, string(buf[:n]))
	if err := netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	gnv, err := gw.h.LinkByName(datapath.GatewayDevice)
	if err != nil {
		t.Fatal(err)
	}
	if gnv.Attrs().Statistics.TxPackets == 0 || gnv.Attrs().Statistics.RxPackets == 0 {
		t.Fatalf("no bidirectional GENEVE packets: %+v", gnv.Attrs().Statistics)
	}
	seenRequest, seenReturn := false, false
	bufOuter := make([]byte, 2048)
	_ = unix.SetsockoptTimeval(captureFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 120000})
	for i := 0; i < 70 && (!seenRequest || !seenReturn); i++ {
		n, _, err := unix.Recvfrom(captureFD, bufOuter, 0)
		if err != nil {
			break
		}
		if n < 50 || binary.BigEndian.Uint16(bufOuter[12:14]) != 0x0800 || bufOuter[23] != 17 || binary.BigEndian.Uint16(bufOuter[36:38]) != datapath.GenevePort {
			continue
		}
		src := net.IP(bufOuter[26:30])
		dst := net.IP(bufOuter[30:34])
		vni := uint32(bufOuter[46])<<16 | uint32(bufOuter[47])<<8 | uint32(bufOuter[48])
		t.Logf("outer Geneve %s -> %s VNI=%d", src, dst, vni)
		if src.Equal(net.ParseIP("10.42.2.4")) && dst.Equal(net.ParseIP(clientIP.String())) && vni == cfg.GatewayID {
			seenReturn = true
		}
		if src.Equal(net.ParseIP(clientIP.String())) && dst.Equal(net.ParseIP("10.42.2.4")) && vni == cfg.GatewayID {
			seenRequest = true
		}
	}
	if !seenRequest || !seenReturn {
		t.Fatalf("missing expected outer Geneve tuple request=%t return=%t", seenRequest, seenReturn)
	}
	// Curl uses TCP; exercise SYN/SYN-ACK and application bytes rather than
	// relying on a UDP conntrack result as evidence for the blocked gate.
	if err := netns.Set(upstreamNS); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("198.19.0.1"), Port: 8081})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		data := make([]byte, 32)
		n, err := conn.Read(data)
		if err != nil {
			serverDone <- err
			return
		}
		if string(data[:n]) != "request" {
			serverDone <- fmt.Errorf("upstream TCP request %q", data[:n])
			return
		}
		_, err = conn.Write([]byte("response"))
		serverDone <- err
	}()
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	stream, err := net.DialTimeout("tcp4", "198.19.0.1:8081", 2*time.Second)
	if err != nil {
		showGatewayCounters(t, gw, gwNS)
		t.Fatalf("TCP request failed: %v", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := stream.Write([]byte("request")); err != nil {
		showGatewayCounters(t, gw, gwNS)
		t.Fatal(err)
	}
	n, err = stream.Read(buf)
	if err != nil {
		showGatewayCounters(t, gw, gwNS)
		t.Fatalf("TCP response failed: %v", err)
	}
	if string(buf[:n]) != "response" {
		t.Fatalf("unexpected TCP payload %q", buf[:n])
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	selected := cc
	selected.Policy = datapath.Policy{Mode: "include", Rules: []datapath.Rule{{CIDRs: []netip.Prefix{netip.MustParsePrefix("198.19.0.1/32")}, Ports: []datapath.Port{{Protocol: "TCP", Port: 8080}, {Protocol: "UDP", Port: 8080}}}}}
	selected.Exclusions = []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("10.43.0.0/16")}
	if err := cl.ApplyClient(context.Background(), selected); err != nil {
		t.Fatal(err)
	}
	clEth, err = cl.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.h.RouteAdd(&netlink.Route{Dst: prefix(netip.MustParsePrefix("0.0.0.0/0")), LinkIndex: clEth.Attrs().Index}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"all", datapath.ClientDevice} {
		for _, kind := range []string{"rp_filter", "src_valid_mark"} {
			b, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + name + "/" + kind)
			if err != nil {
				t.Fatal(err)
			}
			want := "2"
			if kind == "src_valid_mark" {
				want = "0"
			}
			if strings.TrimSpace(string(b)) != want {
				t.Fatalf("%s %s=%q", name, kind, b)
			}
		}
	}
	if err := netns.Set(upstreamNS); err != nil {
		t.Fatal(err)
	}
	_ = upstream.Close()
	selectServer, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("198.19.0.1"), Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	defer selectServer.Close()
	selectedDone := make(chan error, 1)
	go func() {
		conn, e := selectServer.AcceptTCP()
		if e != nil {
			selectedDone <- e
			return
		}
		defer conn.Close()
		_, e = conn.Write([]byte("selected"))
		selectedDone <- e
	}()
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	selectedConn, err := net.DialTimeout("tcp4", "198.19.0.1:8080", 1200*time.Millisecond)
	if err != nil {
		showGatewayCounters(t, gw, gwNS)
		t.Fatalf("selected TCP response with rp_filter=2 failed: %v", err)
	}
	defer selectedConn.Close()
	_ = selectedConn.SetReadDeadline(time.Now().Add(time.Second))
	n, err = selectedConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "selected" {
		t.Fatalf("selected response=%q", buf[:n])
	}
	if err := <-selectedDone; err != nil {
		t.Fatal(err)
	}
	t.Logf("selected TCP response reached PodIP via numbered GENEVE with rp_filter 2")
	if err := netns.Set(upstreamNS); err != nil {
		t.Fatal(err)
	}
	udpSrv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.19.0.1"), Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	defer udpSrv.Close()
	udpDone := make(chan error, 1)
	go func() {
		data := make([]byte, 64)
		_ = udpSrv.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		_, remote, e := udpSrv.ReadFromUDP(data)
		if e == nil {
			_, e = udpSrv.WriteToUDP([]byte("udp-selected"), remote)
		}
		udpDone <- e
	}()
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(clientIP.String())})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := udp.WriteToUDP([]byte("selected"), &net.UDPAddr{IP: net.ParseIP("198.19.0.1"), Port: 8080}); err != nil {
		t.Fatal(err)
	}
	n, _, err = udp.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("selected UDP reply failed: %v", err)
	}
	if string(buf[:n]) != "udp-selected" {
		t.Fatalf("UDP reply=%q", buf[:n])
	}
	if err := <-udpDone; err != nil {
		t.Fatal(err)
	}
	t.Logf("selected UDP response reached PodIP via numbered GENEVE with rp_filter 2")
}
func showGatewayCounters(t *testing.T, gw *Backend, ns netns.NsHandle) {
	t.Helper()
	if err := netns.Set(ns); err != nil {
		t.Fatal(err)
	}
	c := gw.nft()
	chs, err := c.ListChains()
	if err != nil {
		t.Log(err)
		return
	}
	for _, ch := range chs {
		if ch.Table.Name != "ratatoskr_gw" || ch.Name != "forward" {
			continue
		}
		rr, err := c.GetRules(ch.Table, ch)
		if err != nil {
			t.Log(err)
			return
		}
		for i, r := range rr {
			for _, x := range r.Exprs {
				if ct, ok := x.(*expr.Counter); ok {
					t.Logf("forward rule %d packets=%d", i, ct.Packets)
				}
			}
		}
	}
	gnv, err := gw.h.LinkByName(datapath.GatewayDevice)
	if err == nil {
		t.Logf("gateway GENEVE RX=%d TX=%d TX dropped=%d", gnv.Attrs().Statistics.RxPackets, gnv.Attrs().Statistics.TxPackets, gnv.Attrs().Statistics.TxDropped)
	}
	up, err := gw.h.LinkByName(datapath.UpstreamDevice)
	if err == nil {
		t.Logf("gateway upstream RX=%d TX=%d", up.Attrs().Statistics.RxPackets, up.Attrs().Statistics.TxPackets)
	}
}
