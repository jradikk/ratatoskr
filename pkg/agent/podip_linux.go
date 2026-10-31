//go:build linux

package agent

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// verifyTargetPodIPv4 runs inside the verified target netns before any nft,
// routing or link changes. CRI-supplied PodIP must be the sole usable eth0 IPv4
// address; a wrong CRI netns cannot be programmed based solely on its path.
func verifyTargetPodIPv4(expected netip.Addr) error {
	if !expected.Is4() || expected.IsUnspecified() || expected.IsMulticast() {
		return errors.New("selected PodIP is not unicast IPv4")
	}
	eth, err := netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("selected netns eth0 unavailable: %w", err)
	}
	addrs, err := netlink.AddrList(eth, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("list selected eth0 IPv4 addresses: %w", err)
	}
	return matchPodIPv4(expected, addrs)
}

func matchPodIPv4(expected netip.Addr, addrs []netlink.Addr) error {
	if !expected.Is4() || expected.IsUnspecified() || expected.IsMulticast() {
		return errors.New("selected PodIP is not unicast IPv4")
	}
	seen := 0
	for _, a := range addrs {
		if a.IP == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		ip = ip.Unmap()
		if !ok || !ip.Is4() {
			return errors.New("invalid selected eth0 IPv4 address")
		}
		seen++
		if ip != expected {
			return errors.New("selected netns eth0 IPv4 differs from PodIP")
		}
	}
	if seen != 1 {
		return fmt.Errorf("selected netns eth0 requires exactly one PodIP IPv4, found %d", seen)
	}
	return nil
}
