//go:build linux && privileged

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// A real clsact packet path, not Program.Test: after a failed policy update
// the retained priority-419 guard must fence both selected TCP/UDP and an old
// direct pass, without deleting a later foreign CNI filter or using the main
// route as an unprotected fallback. Only a disposable netns/veth is touched.
func TestPrivilegedFailedPolicyUpdatePacketGate(t *testing.T) {
	isolated(t, func(b *Backend) {
		pair := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "eth0", MTU: 1500}, PeerName: "peer0"}
		if err := b.h.LinkAdd(pair); err != nil {
			t.Fatal(err)
		}
		eth, err := b.h.LinkByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		peer, err := b.h.LinkByName("peer0")
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range []struct {
			link netlink.Link
			cidr string
		}{{eth, "10.42.1.8/24"}, {peer, ""}} {
			if x.cidr != "" {
				a, e := netlink.ParseAddr(x.cidr)
				if e != nil {
					t.Fatal(e)
				}
				if e = b.h.AddrAdd(x.link, a); e != nil {
					t.Fatal(e)
				}
			}
			if e := b.h.LinkSetUp(x.link); e != nil {
				t.Fatal(e)
			}
		}
		if err := b.h.NeighSet(&netlink.Neigh{LinkIndex: eth.Attrs().Index, IP: net.ParseIP("10.42.1.1"), HardwareAddr: peer.Attrs().HardwareAddr, State: netlink.NUD_PERMANENT}); err != nil {
			t.Fatal(err)
		}
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: net.ParseIP("10.42.1.1")}); err != nil {
			t.Fatal(err)
		}
		foreign := &netlink.MatchAll{FilterAttrs: netlink.FilterAttrs{LinkIndex: eth.Attrs().Index, Parent: netlink.HANDLE_MIN_EGRESS, Priority: 430, Protocol: unix.ETH_P_ALL}, Actions: []netlink.Action{&netlink.GenericAction{ActionAttrs: netlink.ActionAttrs{Action: netlink.TC_ACT_OK}}}}
		q := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: eth.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}}
		if err := b.h.QdiscAdd(q); err != nil {
			t.Fatal(err)
		}
		if err := b.h.FilterAdd(foreign); err != nil {
			t.Fatal(err)
		}
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), Endpoint: netip.MustParseAddr("10.42.1.9"), GatewayID: 7, MTU: 1400,
			Policy: datapath.Policy{Mode: "include", Rules: []datapath.Rule{{CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")}, Ports: []datapath.Port{{Protocol: "UDP", Port: 8080}, {Protocol: "TCP", Port: 8080}}}}}}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if err := b.VerifyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK, int((unix.ETH_P_ALL&0xff)<<8)|int(unix.ETH_P_ALL>>8))
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: eth.Attrs().Index, Protocol: uint16((unix.ETH_P_ALL&0xff)<<8) | uint16(unix.ETH_P_ALL>>8)}); err != nil {
			t.Fatal(err)
		}
		sendUDP := func(dst string, port int) {
			t.Helper()
			conn, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.42.1.8")})
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			if _, e = conn.WriteToUDP([]byte("fixture"), &net.UDPAddr{IP: net.ParseIP(dst), Port: port}); e != nil {
				t.Fatal(e)
			}
		}
		matching := func(proto byte, port uint16, dst string) bool {
			frame := make([]byte, 2048)
			for {
				n, _, e := unix.Recvfrom(fd, frame, 0)
				if errors.Is(e, unix.EAGAIN) {
					return false
				}
				if e != nil {
					t.Fatal(e)
				}
				if n >= 42 && binary.BigEndian.Uint16(frame[12:14]) == unix.ETH_P_IP && frame[23] == proto && net.IP(frame[30:34]).Equal(net.ParseIP(dst)) && binary.BigEndian.Uint16(frame[36:38]) == port {
					return true
				}
			}
		}
		// Prove the capture/foreign CNI path before failure with a wrong-port pass.
		sendUDP("203.0.113.7", 9090)
		if !matching(unix.IPPROTO_UDP, 9090, "203.0.113.7") {
			t.Fatal("positive direct capture failed; no valid leak oracle")
		}
		// Trigger a failure after installing the update guard. The kernel still
		// retains the previous selector, whose direct policy must NOT be usable.
		changed := c
		changed.Policy.Mode = "invalid"
		if err := b.ApplyClient(context.Background(), changed); err == nil {
			t.Fatal("invalid update accepted")
		}
		guard, err := b.findUpdateGuard(eth)
		if err != nil || guard == nil {
			t.Fatalf("missing fail-closed update guard: %v", err)
		}
		filters, err := b.h.FilterList(eth, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			t.Fatal(err)
		}
		own, foreignFound := false, false
		for _, f := range filters {
			if f.Attrs().Priority == filterPriority {
				own = true
			}
			if f.Attrs().Priority == 430 && f.Attrs().Protocol == unix.ETH_P_ALL {
				foreignFound = true
			}
		}
		if !own || !foreignFound {
			t.Fatalf("old selector or foreign CNI filter altered: own=%t foreign=%t", own, foreignFound)
		}
		before := guard.(*netlink.MatchAll).Actions[0].Attrs().Statistics
		var dropped uint32
		if before != nil && before.Basic != nil {
			dropped = before.Basic.Packets
		}
		sendUDP("203.0.113.7", 8080) // selected
		sendUDP("203.0.113.7", 9090) // old direct pass
		sock, err := net.DialTimeout("tcp4", "203.0.113.7:8080", 250*time.Millisecond)
		if sock != nil {
			_ = sock.Close()
			t.Fatal("selected TCP escaped failed update")
		}
		if err == nil {
			t.Fatal("selected TCP connected")
		}
		if matching(unix.IPPROTO_UDP, 8080, "203.0.113.7") || matching(unix.IPPROTO_UDP, 9090, "203.0.113.7") || matching(unix.IPPROTO_TCP, 8080, "203.0.113.7") {
			t.Fatal("failed update exposed selected or old-direct traffic to eth0")
		}
		until := time.Now().Add(time.Second)
		for {
			guard, err = b.findUpdateGuard(eth)
			if err != nil {
				t.Fatal(err)
			}
			stats := guard.(*netlink.MatchAll).Actions[0].Attrs().Statistics
			if stats != nil && stats.Basic != nil && stats.Basic.Packets >= dropped+2 {
				break
			}
			if time.Now().After(until) {
				t.Fatal("guard action did not count failed-update packets")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := b.VerifyClient(context.Background(), c); err == nil {
			t.Fatal("restart adopted stale selector behind guard")
		}
	})
}
