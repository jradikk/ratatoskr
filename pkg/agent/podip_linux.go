//go:build linux

package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

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
	if err := matchPodIPv4(expected, addrs); err != nil {
		return err
	}
	// Host-like multi-homed namespaces are not selected workload sandboxes.
	// Preserve legitimate loopback, mesh/secondary links and Ratatoskr tunnel
	// addresses; refuse non-Ratatoskr IPv4 on other physical/CNI interfaces.
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list selected netns interfaces: %w", err)
	}
	for _, link := range links {
		name := link.Attrs().Name
		if name == "eth0" || name == "lo" || name == "rtk0" || name == "gnv0" || name == "rtkwg0" {
			continue
		}
		others, err := netlink.AddrList(link, unix.AF_INET)
		if err != nil {
			return fmt.Errorf("inspect selected netns secondary IPv4: %w", err)
		}
		if hostLikeInterface(name, link.Type(), others) {
			return errors.New("selected netns has additional physical IPv4 interface")
		}
	}
	return nil
}

// An extra numbered physical-looking device (not veth/tunnel/mesh link) is a
// host-like shape, not a proof of host identity. The primary defense remains
// the Kubernetes/CRI READY UID, PodIP, pidfd and cgroup identity contract.
func hostLikeInterface(name, kind string, addresses []netlink.Addr) bool {
	if name == "lo" || name == "eth0" || name == "rtk0" || name == "gnv0" || name == "rtkwg0" {
		return false
	}
	// Physical NICs normally have kind "device". In disposable tests the
	// stand-in is a dummy named like a host NIC; do not reject a mesh veth or
	// tun/tap interface just because it has its own IPv4.
	physicalName := strings.HasPrefix(name, "ens") || strings.HasPrefix(name, "eno") ||
		strings.HasPrefix(name, "enp") || strings.HasPrefix(name, "eth") ||
		strings.HasPrefix(name, "wlan")
	if kind != "device" && (kind != "dummy" || !physicalName) {
		return false
	}
	for _, a := range addresses {
		if a.IP != nil {
			return true
		}
	}
	return false
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
