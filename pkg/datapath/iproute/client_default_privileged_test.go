//go:build linux && privileged

package iproute

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// TCP initially resolves via main before route/OUTPUT marking. On withdrawal,
// the selected SYN is denied at reroute, but connect can time out rather than
// synchronously returning EHOSTUNREACH; timeout alone is never fail-close proof.
func TestPrivilegedClientWithdrawSelectedTCPConnect(t *testing.T) {
	for _, mode := range []string{"none", "wireguard"} {
		t.Run(mode, func(t *testing.T) {
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
				for _, item := range []struct {
					link netlink.Link
					cidr string
				}{{eth, "10.42.1.8/24"}, {peer, ""}} {
					if item.cidr != "" {
						addr, e := netlink.ParseAddr(item.cidr)
						if e != nil {
							t.Fatal(e)
						}
						if e = b.h.AddrAdd(item.link, addr); e != nil {
							t.Fatal(e)
						}
					}
					if e := b.h.LinkSetUp(item.link); e != nil {
						t.Fatal(e)
					}
				}
				// The next hop is not a local address in this namespace;
				// static neighbor keeps the veth carrier usable without ARP.
				if e := b.h.NeighSet(&netlink.Neigh{LinkIndex: eth.Attrs().Index, IP: net.ParseIP("10.42.1.1"), HardwareAddr: peer.Attrs().HardwareAddr, State: netlink.NUD_PERMANENT}); e != nil {
					t.Fatal(e)
				}
				if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: net.ParseIP("10.42.1.1")}); err != nil {
					t.Fatal(err)
				}
				cfg := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"),
					Endpoint: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 1320,
					Encryption: mode, Policy: datapath.Policy{Mode: "include", Rules: []datapath.Rule{{
						CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")},
						Ports: []datapath.Port{{Protocol: "TCP", Port: 8080}},
					}}}}
				if mode == "wireguard" {
					key, err := wgtypes.GeneratePrivateKey()
					if err != nil {
						t.Fatal(err)
					}
					cfg.GatewayPublicKey = key.PublicKey().String()
					cfg.RegistrationCACert = "public-test-CA-placeholder"
				}
				if err := b.ApplyClient(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				cfg.Endpoint = netip.Addr{}
				if err := b.ApplyClient(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				// The target matches the selector, not an exclusion. Verify the
				// selected marked lookup is unreachable, independently of connect.
				_, err = netlink.RouteGetWithOptions(net.ParseIP("198.51.100.7"),
					&netlink.RouteGetOptions{Mark: steeringMark})
				if !errors.Is(err, unix.EHOSTUNREACH) && !errors.Is(err, unix.ENETUNREACH) {
					t.Fatalf("selected RPDB route escaped: %v", err)
				}
				// Count only IPv4 TCP frames headed to the selected destination on
				// eth0. Packet socket is bound to the disposable netns veth;
				// it never observes any host or cluster interface.
				fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK,
					int((unix.ETH_P_ALL&0xff)<<8)|int(unix.ETH_P_ALL>>8))
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fd)
				if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: eth.Attrs().Index,
					Protocol: uint16((unix.ETH_P_ALL&0xff)<<8) | uint16(unix.ETH_P_ALL>>8)}); err != nil {
					t.Fatal(err)
				}
				// Positive capture control: a wrong-port unselected packet MUST be
				// visible leaving eth0 via the known veth neighbor.
				wrongPort, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.42.1.8")})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = wrongPort.WriteToUDP([]byte("control"), &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 9090}); err != nil {
					t.Fatal(err)
				}
				_ = wrongPort.Close()
				frame := make([]byte, 2048)
				controlSeen := false
				for {
					n, _, e := unix.Recvfrom(fd, frame, 0)
					if errors.Is(e, unix.EAGAIN) {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
					if n >= 14 {
					}
					if n >= 42 && binary.BigEndian.Uint16(frame[12:14]) == unix.ETH_P_IP && frame[23] == unix.IPPROTO_UDP && net.IP(frame[30:34]).Equal(net.ParseIP("198.51.100.7")) && binary.BigEndian.Uint16(frame[36:38]) == 9090 {
						controlSeen = true
					}
				}
				if !controlSeen {
					t.Fatal("positive eth0 capture missed wrong-port direct packet")
				}
				start := time.Now()
				conn, err := net.DialTimeout("tcp4", "198.51.100.7:8080", 350*time.Millisecond)
				if conn != nil {
					_ = conn.Close()
					t.Fatal("selected TCP connected on unhealthy gateway")
				}
				if !os.IsTimeout(err) || time.Since(start) < 300*time.Millisecond {
					t.Fatalf("expected bounded TCP timeout, got %v", err)
				}
				for {
					n, _, err := unix.Recvfrom(fd, frame, 0)
					if errors.Is(err, unix.EAGAIN) {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					if n >= 54 && binary.BigEndian.Uint16(frame[12:14]) == unix.ETH_P_IP &&
						frame[23] == unix.IPPROTO_TCP && net.IP(frame[30:34]).Equal(net.ParseIP("198.51.100.7")) &&
						binary.BigEndian.Uint16(frame[36:38]) == 8080 {
						t.Fatal("selected TCP SYN escaped directly onto eth0")
					}
				}
				// The direct in-cluster path remains available; a timeout to the
				// selected destination never counts as proof of this by itself.
				routes, err := netlink.RouteGetWithOptions(net.ParseIP("10.42.1.10"), &netlink.RouteGetOptions{})
				if err != nil || len(routes) != 1 || routes[0].LinkIndex != eth.Attrs().Index {
					t.Fatalf("direct in-cluster route lost: %v %v", routes, err)
				}
			})
		})
	}
}

func TestPrivilegedClientWithdrawSelectedUDPFailsClosed(t *testing.T) {
	for _, mode := range []string{"none", "wireguard"} {
		t.Run(mode, func(t *testing.T) {
			isolated(t, func(b *Backend) {
				eth := dummy(t, b, "eth0", "10.42.1.8/24")
				if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: net.ParseIP("10.42.1.1")}); err != nil {
					t.Fatal(err)
				}
				before := mainRoutes(t, b)
				cfg := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), Endpoint: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 1320, Encryption: mode,
					Policy: datapath.Policy{Mode: "include", Rules: []datapath.Rule{{CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}, Ports: []datapath.Port{{Protocol: "UDP", Port: 8080}}}}}}
				if mode == "wireguard" {
					key, err := wgtypes.GeneratePrivateKey()
					if err != nil {
						t.Fatal(err)
					}
					cfg.GatewayPublicKey = key.PublicKey().String()
					cfg.RegistrationCACert = "public-test-CA-placeholder"
				}
				if err := b.ApplyClient(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				cfg.Endpoint = netip.Addr{}
				if err := b.ApplyClient(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				_, err := netlink.RouteGetWithOptions(net.ParseIP("198.51.100.7"), &netlink.RouteGetOptions{Mark: steeringMark})
				if !errors.Is(err, unix.EHOSTUNREACH) && !errors.Is(err, unix.ENETUNREACH) {
					t.Fatalf("selected marked lookup escaped closed table: %v", err)
				}
				conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.42.1.8")})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_, err = conn.WriteToUDP([]byte("selected"), &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 8080})
				if !errors.Is(err, unix.EHOSTUNREACH) && !errors.Is(err, unix.ENETUNREACH) {
					t.Fatalf("selected UDP did not fail closed: %v", err)
				}
				if !reflect.DeepEqual(before, mainRoutes(t, b)) {
					t.Fatal("direct API/main route changed")
				}
				r, err := netlink.RouteGetWithOptions(net.ParseIP("10.42.1.10"), &netlink.RouteGetOptions{})
				if err != nil || len(r) != 1 || r[0].LinkIndex != eth.Attrs().Index {
					t.Fatalf("direct pod/API route unavailable: %v %v", r, err)
				}
				cfg.Endpoint = netip.MustParseAddr("10.42.2.4")
				if err := b.ApplyClient(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				selected, err := netlink.RouteGetWithOptions(net.ParseIP("198.51.100.7"), &netlink.RouteGetOptions{Mark: steeringMark})
				if err != nil || len(selected) != 1 || selected[0].LinkIndex == eth.Attrs().Index {
					t.Fatalf("selected tunnel did not recover: %v %v", selected, err)
				}
			})
		})
	}
}

// Kernel RouteListFiltered decodes a default as explicit 0.0.0.0/0. A lost
// endpoint must withdraw ONLY our unicast path while keeping unrelated routes.
func TestPrivilegedClientDefaultWithdrawAndRecovery(t *testing.T) {
	for _, mode := range []string{"none", "wireguard"} {
		t.Run(mode, func(t *testing.T) {
			isolated(t, func(b *Backend) {
				eth := dummy(t, b, "eth0", "10.42.1.8/24")
				if err := b.h.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: net.ParseIP("10.42.1.1")}); err != nil {
					t.Fatal(err)
				}
				mainBefore := mainRoutes(t, b)
				cfg := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), Endpoint: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 1320, Encryption: mode}
				if mode == "wireguard" {
					key, err := wgtypes.GeneratePrivateKey()
					if err != nil {
						t.Fatal(err)
					}
					cfg.GatewayPublicKey = key.PublicKey().String()
					cfg.RegistrationCACert = "public-test-CA-placeholder"
				}
				if err := b.ApplyClient(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				table := datapath.ClientTable(cfg.GatewayID)
				ownedDefault := func() bool {
					t.Helper()
					routes, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, route := range routes {
						if route.Type == unix.RTN_UNICAST && int(route.Protocol) == datapath.RouteProtocol && isIPv4Default(route.Dst) {
							if found {
								t.Fatal("duplicate owned default")
							}
							found = true
							if route.Dst == nil || route.Dst.String() != "0.0.0.0/0" {
								t.Fatalf("kernel route decoder no explicit default: %v", route.Dst)
							}
						}
					}
					return found
				}
				if !ownedDefault() {
					t.Fatal("healthy client default absent")
				}
				// Foreign same-table unicast host route and foreign default with a
				// different metric are never owned by our transition.
				foreignHost := netlink.Route{Family: unix.AF_INET, Table: table, Dst: host(netip.MustParseAddr("198.51.100.2")), LinkIndex: eth.Attrs().Index, Protocol: 99}
				if err := b.h.RouteAdd(&foreignHost); err != nil {
					t.Fatal(err)
				}
				foreignDefault := netlink.Route{Family: unix.AF_INET, Table: table, Dst: prefix(netip.MustParsePrefix("0.0.0.0/0")), LinkIndex: eth.Attrs().Index, Priority: 100, Protocol: 99}
				if err := b.h.RouteAdd(&foreignDefault); err != nil {
					t.Fatal(err)
				}
				cfg.Endpoint = netip.Addr{}
				if err := b.ApplyClient(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				if ownedDefault() {
					t.Fatal("lost endpoint retained owned unicast default")
				}
				routes, err := b.h.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
				if err != nil {
					t.Fatal(err)
				}
				foreignHostSeen, foreignDefaultSeen, fallbackSeen, metadataSeen := false, false, false, false
				for _, r := range routes {
					if r.Dst != nil && r.Dst.String() == "198.51.100.2/32" && int(r.Protocol) == 99 {
						foreignHostSeen = true
					}
					if isIPv4Default(r.Dst) && r.Type == unix.RTN_UNICAST && int(r.Protocol) == 99 {
						foreignDefaultSeen = true
					}
					if isIPv4Default(r.Dst) && r.Type == unix.RTN_UNREACHABLE && int(r.Protocol) == datapath.RouteProtocol {
						fallbackSeen = true
					}
					if r.Dst != nil && r.Dst.String() == "169.254.169.254/32" && r.Type == unix.RTN_PROHIBIT {
						metadataSeen = true
					}
				}
				if !foreignHostSeen || !foreignDefaultSeen || !fallbackSeen || !metadataSeen {
					t.Fatalf("unhealthy transition changed foreign/fallback/metadata routes: host=%t foreign=%t fallback=%t metadata=%t", foreignHostSeen, foreignDefaultSeen, fallbackSeen, metadataSeen)
				}
				// FIB lookup must NOT pick our selected tunnel route. The
				// foreign route remains present but is not authorized to become
				// an alternate selected path in production (test-only fixture).
				marked, err := netlink.RouteGetWithOptions(net.ParseIP("203.0.113.7"), &netlink.RouteGetOptions{Mark: steeringMark})
				if err != nil && !errors.Is(err, unix.EHOSTUNREACH) && !errors.Is(err, unix.ENETUNREACH) {
					t.Fatalf("unexpected selected lookup: %v", err)
				}
				for _, r := range marked {
					if int(r.Protocol) == datapath.RouteProtocol && r.Type == unix.RTN_UNICAST {
						t.Fatal("selected lookup retained owned tunnel")
					}
				}
				if !reflect.DeepEqual(mainBefore, mainRoutes(t, b)) {
					t.Fatal("withdrawal changed direct main/API route")
				}
				cfg.Endpoint = netip.MustParseAddr("10.42.2.4")
				if err := b.ApplyClient(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				if !ownedDefault() {
					t.Fatal("healthy recovery failed to re-add tunnel default")
				}
			})
		})
	}
}
