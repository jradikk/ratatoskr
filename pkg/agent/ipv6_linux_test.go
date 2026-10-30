//go:build linux

package agent

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestGlobalIPv6Selection(t *testing.T) {
	cases := []struct {
		name  string
		addrs []netlink.Addr
		want  bool
	}{
		{"none", nil, false},
		{"link local", []netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("fe80::2"), Mask: net.CIDRMask(64, 128)}}}, false},
		{"unspecified", []netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("::"), Mask: net.CIDRMask(128, 128)}}}, false},
		{"globally routable", []netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}}}, true},
		{"ULA", []netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("fd12::2"), Mask: net.CIDRMask(64, 128)}}}, true},
		{"late dual stack", []netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("fe80::2"), Mask: net.CIDRMask(64, 128)}}, {IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::2"), Mask: net.CIDRMask(64, 128)}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := globalIPv6(tc.addrs); got != tc.want {
				t.Fatalf("globalIPv6=%t, want %t", got, tc.want)
			}
		})
	}
}
