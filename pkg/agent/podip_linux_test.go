//go:build linux

package agent

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
)

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
