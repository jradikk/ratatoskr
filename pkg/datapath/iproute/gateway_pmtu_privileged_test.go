//go:build linux && privileged

package iproute

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func TestPrivilegedGatewayLowCarrierPMTU(t *testing.T) {
	gatewayBidirectionalReturn(t, 900, 700, 750)
	// Below the IPv4 minimum is rejected without creating a tunnel. The
	// check is separate from the proven successful 700-byte packet path.
	isolated(t, func(b *Backend) {
		_ = dummy(t, b, "eth0", "10.42.1.8/24")
		cfg := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 575, Endpoint: netip.MustParseAddr("10.42.2.4")}
		if err := b.ApplyClient(context.Background(), cfg); err == nil {
			t.Fatal("below-minimum client MTU accepted")
		}
		if _, err := b.h.LinkByName(datapath.ClientDevice); err == nil {
			t.Fatal("invalid MTU created GENEVE link")
		}
	})
	isolated(t, func(b *Backend) {
		_ = dummy(t, b, "eth0", "10.42.2.4/24")
		cfg := datapath.GatewayConfig{PodIP: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 575}
		if err := b.ApplyGateway(context.Background(), cfg); err == nil {
			t.Fatal("below-minimum gateway MTU accepted")
		}
		if _, err := b.h.LinkByName(datapath.GatewayDevice); err == nil {
			t.Fatal("invalid gateway MTU created GENEVE link")
		}
	})
}

// verifyLowMTUPayloads runs on the established, actually forwarding three-netns
// fixture after baseline UDP/TCP request+reply, not on isolated route metadata.
func verifyLowMTUPayloads(t *testing.T, gw, cl *Backend, gatewayNS, clientNS, upstreamNS netns.NsHandle, innerMTU, carrierMTU, upstreamMTU int) {
	t.Helper()
	if innerMTU > carrierMTU-50 || innerMTU > upstreamMTU {
		t.Fatal("inner MTU exceeds low carrier/upstream")
	}
	if err := netns.Set(gatewayNS); err != nil {
		t.Fatal(err)
	}
	geneve, err := gw.h.LinkByName("gnv0")
	if err != nil {
		t.Fatal(err)
	}
	if geneve.Attrs().MTU != innerMTU {
		t.Fatal("gateway GENEVE MTU differs")
	}
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	clientGeneve, err := cl.h.LinkByName("rtk0")
	if err != nil {
		t.Fatal(err)
	}
	if clientGeneve.Attrs().MTU != innerMTU {
		t.Fatal("client GENEVE MTU differs")
	}
	// A payload several times carrier MTU must cross both GENEVE and the lower
	// upstream0 MTU. It is compared byte-for-byte, not just by successful dial.
	data := make([]byte, 16*1024)
	for i := range data {
		data[i] = byte(i*131 + 17)
	}
	if err := netns.Set(upstreamNS); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("198.19.0.1"), Port: 8082})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	reply := make(chan error, 1)
	go func() {
		s, e := listener.AcceptTCP()
		if e != nil {
			reply <- e
			return
		}
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(3 * time.Second))
		input := make([]byte, len(data))
		_, e = io.ReadFull(s, input)
		if e == nil && !bytes.Equal(input, data) {
			e = errors.New("upstream TCP payload mismatch")
		}
		if e == nil {
			_, e = s.Write(input)
		}
		reply <- e
	}()
	if err = netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	stream, err := net.DialTimeout("tcp4", "198.19.0.1:8082", 2*time.Second)
	if err != nil {
		t.Fatalf("low-MTU TCP dial failed: %v", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = stream.Write(data); err != nil {
		t.Fatal(err)
	}
	output := make([]byte, len(data))
	if _, err = io.ReadFull(stream, output); err != nil {
		t.Fatalf("large TCP return payload failed: %v", err)
	}
	if !bytes.Equal(output, data) {
		t.Fatal("large TCP return corrupted")
	}
	if err = <-reply; err != nil {
		t.Fatal(err)
	}
	// Keep a header-only bound capture on the client CNI link. A selected
	// oversized datagram must not become plaintext on eth0 if PMTU fails.
	eth, err := cl.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	packetFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK,
		int((unix.ETH_P_ALL<<8)|(unix.ETH_P_ALL>>8)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(packetFD)
	if err := unix.Bind(packetFD, &unix.SockaddrLinklayer{Ifindex: eth.Attrs().Index,
		Protocol: uint16((unix.ETH_P_ALL << 8) | (unix.ETH_P_ALL >> 8))}); err != nil {
		t.Fatal(err)
	}
	// A selected DF UDP datagram larger than the inner GENEVE MTU must
	// synchronously fail EMSGSIZE rather than escape onto the plain main route.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
		t.Fatal(err)
	}
	if err = unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{10, 42, 3, 8}}); err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, innerMTU+100)
	_, err = unix.SendmsgN(fd, oversized, nil, &unix.SockaddrInet4{Addr: [4]byte{198, 19, 0, 1}, Port: 8083}, 0)
	if !errors.Is(err, unix.EMSGSIZE) {
		t.Fatalf("DF UDP oversize did not report EMSGSIZE: %v", err)
	}
	frame := make([]byte, 2048)
	for {
		n, _, e := unix.Recvfrom(packetFD, frame, 0)
		if errors.Is(e, unix.EAGAIN) {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if n >= 42 && binary.BigEndian.Uint16(frame[12:14]) == unix.ETH_P_IP && frame[23] == unix.IPPROTO_UDP &&
			net.IP(frame[30:34]).Equal(net.ParseIP("198.19.0.1")) && binary.BigEndian.Uint16(frame[36:38]) == 8083 {
			t.Fatal("oversized selected UDP escaped in plaintext on client eth0")
		}
	}
}
