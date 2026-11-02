//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

var geneveClientAddress = netip.MustParsePrefix("169.254.64.2/32")

// ensureGeneveAddress refuses foreign IPv4 assignments instead of changing
// CNI or other workloads' addressing. The GENEVE device's explicit client
// PodIP tunnel source remains untouched; no proc sysctl writes are needed.
func (b *Backend) ensureGeneveAddress(link netlink.Link) error {
	addrs, err := b.h.AddrList(link, unix.AF_INET)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok || !ip.Is4() || a.IPNet == nil {
			return fmt.Errorf("unexpected IPv4 address on %s", datapath.GatewayDevice)
		}
		ones, bits := a.Mask.Size()
		if bits != 32 || netip.PrefixFrom(ip, ones).Masked() != geneveClientAddress {
			return fmt.Errorf("foreign/conflicting IPv4 address %s on %s", a.IPNet, datapath.GatewayDevice)
		}
	}
	if len(addrs) == 1 {
		return nil
	}
	v := geneveClientAddress.Addr().As4()
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(v[:]), Mask: net.CIDRMask(32, 32)}, Label: datapath.GatewayDevice}
	if err := b.h.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("assign owned client GENEVE address: %w", err)
	}
	return nil
}

func (b *Backend) verifyGeneveAddress(link netlink.Link) error {
	addrs, err := b.h.AddrList(link, unix.AF_INET)
	if err != nil {
		return err
	}
	if len(addrs) != 1 {
		return fmt.Errorf("expected exactly one owned IPv4 address on %s", datapath.GatewayDevice)
	}
	addr := addrs[0]
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok || !ip.Is4() || addr.IPNet == nil {
		return fmt.Errorf("invalid client GENEVE address")
	}
	ones, bits := addr.Mask.Size()
	if bits != 32 || netip.PrefixFrom(ip, ones).Masked() != geneveClientAddress {
		return fmt.Errorf("client GENEVE address is not owned %s", geneveClientAddress)
	}
	return nil
}
