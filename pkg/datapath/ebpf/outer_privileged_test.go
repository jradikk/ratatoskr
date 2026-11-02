//go:build linux && privileged

package ebpf

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// Capture the kernel's emitted GENEVE packet on the pod underlay. This low-level
// component probe does not create a cluster or run the project traffic suite.
func TestPrivilegedGeneveOuterHeaderAndIdentityTLV(t *testing.T) {
	isolated(t, func(b *Backend) {
		dummy(t, b)
		eth, err := b.h.LinkByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		endpoint := net.ParseIP("10.42.1.9")
		mac, _ := net.ParseMAC("02:00:00:00:00:09")
		if err := b.h.NeighSet(&netlink.Neigh{LinkIndex: eth.Attrs().Index, IP: endpoint, HardwareAddr: mac, State: netlink.NUD_PERMANENT}); err != nil {
			t.Fatal(err)
		}
		c := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), Endpoint: netip.MustParseAddr("10.42.1.9"), GatewayID: 7, MTU: 1400, Identity: datapath.Identity{Namespace: "unit", UID: "pod-uid"}}
		if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}); err != nil {
			t.Fatal(err)
		}
		if err := b.ApplyClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int((unix.ETH_P_ALL<<8)|(unix.ETH_P_ALL>>8)))
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16((unix.ETH_P_ALL << 8) | (unix.ETH_P_ALL >> 8)), Ifindex: eth.Attrs().Index}); err != nil {
			t.Fatal(err)
		}
		tv := unix.NsecToTimeval((1500 * time.Millisecond).Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			t.Fatal(err)
		}
		sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.42.1.8")})
		if err != nil {
			t.Fatal(err)
		}
		defer sock.Close()
		if _, err := sock.WriteToUDP([]byte("outer-header"), &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		for i := 0; i < 20; i++ {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				t.Fatalf("no GENEVE outer frame: %v", err)
			}
			if n < 54 || buf[12] != 8 || buf[13] != 0 || buf[23] != 17 || binary.BigEndian.Uint16(buf[36:38]) != datapath.GenevePort {
				continue
			}
			if !net.IP(buf[26:30]).Equal(net.ParseIP("10.42.1.8")) || !net.IP(buf[30:34]).Equal(endpoint) {
				t.Fatalf("GENEVE outer source/destination unexpected: %s -> %s", net.IP(buf[26:30]), net.IP(buf[30:34]))
			}
			if got := uint32(buf[46])<<16 | uint32(buf[47])<<8 | uint32(buf[48]); got != c.GatewayID {
				t.Fatalf("GENEVE VNI=%d want %d", got, c.GatewayID)
			}
			opt := identityTLV(c)
			if buf[42]&0x3f != 3 || binary.BigEndian.Uint16(buf[50:52]) != 0x5254 || buf[52] != opt.Type || buf[53] != opt.Len {
				t.Fatalf("GENEVE identity TLV absent or malformed: option bytes %x", buf[42:54])
			}
			if string(buf[54:62]) != string(opt.Identity[:]) {
				t.Fatal("GENEVE identity TLV hash differs from client identity")
			}
			return
		}
		t.Fatal("outbound GENEVE frame not captured on eth0")
	})
}
