//go:build linux && privileged

package agent

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// A selected namespace retains IPv6 deny hooks even when CNI assigns a
// global IPv6 address after IPv4 programming. IPv4 remains available and the
// readiness marker stays UP. Disposable netns/veth only; no host or CNI edits.
func TestPrivilegedLateIPv6PacketsRemainIPv6OnlyBlocked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root CAP_SYS_ADMIN/NET_ADMIN")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	selected, err := netns.New()
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("CAP_SYS_ADMIN unavailable")
		}
		t.Fatal(err)
	}
	defer func() {
		if e := netns.Set(original); e != nil {
			t.Error(e)
		}
		_ = selected.Close()
	}()
	pair := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "eth0", MTU: 1500}, PeerName: "peer0"}
	if err = netlink.LinkAdd(pair); err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName("peer0")
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := netns.Set(original); e != nil {
			t.Error(e)
		}
		_ = sibling.Close()
	}()
	if err = netns.Set(selected); err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetNsFd(peer, int(sibling)); err != nil {
		t.Fatal(err)
	}
	if err = netns.Set(selected); err != nil {
		t.Fatal(err)
	}
	eth, err := netlink.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	address := func(l netlink.Link, raw string) {
		t.Helper()
		a, e := netlink.ParseAddr(raw)
		if e != nil {
			t.Fatal(e)
		}
		if e = netlink.AddrAdd(l, a); e != nil {
			t.Fatal(e)
		}
	}
	address(eth, "10.42.1.8/24")
	address(eth, "2001:db8::8/64")
	if err = netlink.LinkSetUp(eth); err != nil {
		t.Fatal(err)
	}
	if err = netns.Set(sibling); err != nil {
		t.Fatal(err)
	}
	peer, err = netlink.LinkByName("peer0")
	if err != nil {
		t.Fatal(err)
	}
	address(peer, "10.42.1.9/24")
	address(peer, "2001:db8::9/64")
	if err = netlink.LinkSetUp(peer); err != nil {
		t.Fatal(err)
	}
	// Wait for normal IPv6 DAD to finish on both throwaway links; do not
	// disable DAD or change any node/host sysctl to make this test pass.
	readyIPv6 := func(ns netns.NsHandle, name, ip string) {
		t.Helper()
		until := time.Now().Add(4 * time.Second)
		for time.Now().Before(until) {
			if e := netns.Set(ns); e != nil {
				t.Fatal(e)
			}
			l, e := netlink.LinkByName(name)
			if e != nil {
				t.Fatal(e)
			}
			addrs, e := netlink.AddrList(l, unix.AF_INET6)
			if e != nil {
				t.Fatal(e)
			}
			for _, addr := range addrs {
				if addr.IP.Equal(net.ParseIP(ip)) && addr.Flags&unix.IFA_F_TENTATIVE == 0 {
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("disposable IPv6 address never completed DAD")
	}
	readyIPv6(selected, "eth0", "2001:db8::8")
	readyIPv6(sibling, "peer0", "2001:db8::9")
	if err = netns.Set(sibling); err != nil {
		t.Fatal(err)
	}
	// AF_PACKET observes only the peer of the disposable selected namespace;
	// upper-layer timeouts alone never qualify as absence of IPv4/IPv6 traffic.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK, int((unix.ETH_P_ALL&0xff)<<8)|int(unix.ETH_P_ALL>>8))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: peer.Attrs().Index, Protocol: uint16((unix.ETH_P_ALL&0xff)<<8) | uint16(unix.ETH_P_ALL>>8)}); err != nil {
		t.Fatal(err)
	}
	visible := func(proto uint16, dst net.IP, wait time.Duration) bool {
		t.Helper()
		until := time.Now().Add(wait)
		buf := make([]byte, 2048)
		for time.Now().Before(until) {
			n, _, e := unix.Recvfrom(fd, buf, 0)
			if errors.Is(e, unix.EAGAIN) {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if e != nil {
				t.Fatal(e)
			}
			if n < 42 || binary.BigEndian.Uint16(buf[12:14]) != proto {
				continue
			}
			if proto == unix.ETH_P_IP && net.IP(buf[30:34]).Equal(dst.To4()) {
				return true
			}
			if proto == unix.ETH_P_IPV6 && net.IP(buf[38:54]).Equal(dst.To16()) {
				return true
			}
		}
		return false
	}
	send := func(network, address string) error {
		t.Helper()
		if err := netns.Set(selected); err != nil {
			t.Fatal(err)
		}
		c, e := net.DialTimeout(network, address, time.Second)
		if e != nil {
			return e
		}
		defer c.Close()
		_, e = c.Write([]byte("selected"))
		return e
	}
	// UDP sockets with an allocated local source generate a packet even without
	// a receiver. Capture both families BEFORE installing the namespace guards.
	if err := send("udp4", "10.42.1.9:8080"); err != nil {
		t.Fatal(err)
	}
	if err = netns.Set(sibling); err != nil {
		t.Fatal(err)
	}
	if !visible(unix.ETH_P_IP, net.ParseIP("10.42.1.9"), time.Second) {
		t.Fatal("positive IPv4 capture absent")
	}
	if err = send("udp6", "[2001:db8::9]:8080"); err != nil {
		t.Fatal(err)
	}
	if err = netns.Set(sibling); err != nil {
		t.Fatal(err)
	}
	if !visible(unix.ETH_P_IPV6, net.ParseIP("2001:db8::9"), time.Second) {
		t.Fatal("positive IPv6 capture absent")
	}
	if err = netns.Set(selected); err != nil {
		t.Fatal(err)
	}
	// Emulate successful initial programming before CNI's late IPv6 assignment.
	v6, err := netlink.ParseAddr("2001:db8::8/64")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.AddrDel(eth, v6); err != nil {
		t.Fatal(err)
	}
	if err = inspectAndGuard(); err != nil {
		t.Fatal(err)
	}
	// Model an already healthy selected Pod before the late IPv6 assignment.
	// IPv6 must be blocked without withdrawing IPv4 or its readiness marker.
	marker := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: Marker}}
	if err = netlink.LinkAdd(marker); err != nil {
		t.Fatal(err)
	}
	created, err := netlink.LinkByName(Marker)
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(created); err != nil {
		t.Fatal(err)
	}
	// The IPv6 hook is already active, BEFORE the late address returns.
	// With no local global IPv6 source the socket itself may fail EADDRNOTAVAIL;
	// absence of packets is still checked, but that error alone is not proof.
	if err = send("udp6", "[2001:db8::9]:8080"); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) && !errors.Is(err, unix.ENETUNREACH) {
		t.Fatal(err)
	}
	if err = netns.Set(sibling); err != nil {
		t.Fatal(err)
	}
	if visible(unix.ETH_P_IPV6, net.ParseIP("2001:db8::9"), 150*time.Millisecond) {
		t.Fatal("IPv6 leaked after guard")
	}
	if err = netns.Set(selected); err != nil {
		t.Fatal(err)
	}
	address(eth, "2001:db8::8/64")
	if err = guardWorkload(); err != nil {
		t.Fatalf("dual-stack address incorrectly blocked IPv4: %v", err)
	}
	readyMarker, err := netlink.LinkByName(Marker)
	if err != nil || !markerReady(readyMarker) {
		t.Fatalf("dual-stack address withdrew healthy IPv4 readiness: %v", err)
	}
	blocked, err := quarantined()
	if err != nil || blocked {
		t.Fatalf("dual-stack address installed IPv4 quarantine: %t %v", blocked, err)
	}
	if err = send("udp4", "10.42.1.9:8080"); err != nil {
		t.Fatalf("dual-stack address broke IPv4 direct route: %v", err)
	}
	if err = netns.Set(sibling); err != nil {
		t.Fatal(err)
	}
	if !visible(unix.ETH_P_IP, net.ParseIP("10.42.1.9"), time.Second) {
		t.Fatal("IPv4 packet absent after global IPv6 assignment")
	}
	if err = send("udp6", "[2001:db8::9]:8080"); err != nil && !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EADDRNOTAVAIL) && !errors.Is(err, unix.ENETUNREACH) {
		t.Fatal(err)
	}
	if err = netns.Set(sibling); err != nil {
		t.Fatal(err)
	}
	if visible(unix.ETH_P_IPV6, net.ParseIP("2001:db8::9"), 150*time.Millisecond) {
		t.Fatal("late IPv6 escaped existing guard")
	}
	if err = netns.Set(selected); err != nil {
		t.Fatal(err)
	}
	if err = netlink.AddrDel(eth, v6); err != nil {
		t.Fatal(err)
	}
	if err = inspectAndGuard(); err != nil {
		t.Fatalf("IPv4 path changed after removing IPv6 address: %v", err)
	}
}
