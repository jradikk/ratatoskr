//go:build linux

package agent

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestHostLikeExtraPhysicalIPv4IsRefusedWithoutRejectingMeshLinks(t *testing.T) {
	address := netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.5.0.9"), Mask: net.CIDRMask(24, 32)}}
	for _, tc := range []struct {
		name, kind string
		addrs      []netlink.Addr
		want       bool
	}{
		{"ens5", "device", []netlink.Addr{address}, true},
		{"enp1s0", "device", []netlink.Addr{address}, true},
		{"eth1", "device", []netlink.Addr{address}, true},
		{"eth0", "device", []netlink.Addr{address}, false},
		{"lo", "device", []netlink.Addr{address}, false},
		{"mesh0", "veth", []netlink.Addr{address}, false},
		{"tun0", "tun", []netlink.Addr{address}, false},
		{"rtkwg0", "device", []netlink.Addr{address}, false},
		{"ens5", "device", nil, false},
	} {
		if got := hostLikeInterface(tc.name, tc.kind, tc.addrs); got != tc.want {
			t.Fatalf("%s (%s) host-like=%v want=%v", tc.name, tc.kind, got, tc.want)
		}
	}
}

func TestSelectedNamespaceIPv4MustExactlyMatchPodIP(t *testing.T) {
	expected := netip.MustParseAddr("10.5.0.7")
	address := func(s string) netlink.Addr {
		return netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP(s), Mask: net.CIDRMask(24, 32)}}
	}
	for _, tc := range []struct {
		name      string
		addrs     []netlink.Addr
		wantError bool
	}{
		{"correct single", []netlink.Addr{address("10.5.0.7")}, false},
		{"no address", nil, true},
		{"wrong sandbox", []netlink.Addr{address("10.5.0.8")}, true},
		{"duplicate PodIP", []netlink.Addr{address("10.5.0.7"), address("10.5.0.7")}, true},
		{"additional IPv4", []netlink.Addr{address("10.5.0.7"), address("10.5.0.8")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := matchPodIPv4(expected, tc.addrs)
			if (err != nil) != tc.wantError {
				t.Fatalf("matchPodIPv4 returned %v; expected error=%v", err, tc.wantError)
			}
		})
	}
}
