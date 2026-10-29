//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func populate(objects *clientObjects, c datapath.ClientConfig, link netlink.Link) error {
	cfg := clientClientConfig{PodIp: addrU32(c.PodIP), GatewayId: c.GatewayID}
	cfg.GatewayMac = [6]byte{0x02, 0x52, 0x54, 0x4b, 0x00, 0x02}
	if c.AllowCloudMetadata {
		cfg.AllowMetadata = 1
	}
	switch c.Policy.Mode {
	case "include":
		cfg.Mode = 1
	case "exclude":
		cfg.Mode = 2
	}
	if link != nil && c.Endpoint.IsValid() {
		cfg.Ifindex = uint32(link.Attrs().Index)                     // #nosec G115 -- Linux ifindex is a positive 32-bit value.
		cfg.Endpoint = binary.BigEndian.Uint32(c.Endpoint.AsSlice()) // BPF helper converts host-order u32 with cpu_to_be32.
		cfg.Healthy = 1
	}
	zero := uint32(0)
	if err := objects.Config.Put(zero, cfg); err != nil {
		return err
	}
	if err := objects.Identity.Put(zero, identityTLV(c)); err != nil {
		return err
	}
	exclusions := map[netip.Prefix]bool{netip.MustParsePrefix("169.254.0.0/16"): true}
	if c.Endpoint.IsValid() {
		exclusions[netip.PrefixFrom(c.Endpoint, 32)] = true
	}
	for _, p := range c.Exclusions {
		exclusions[p.Masked()] = true
	}
	for _, p := range c.Policy.ExcludeCIDRs {
		exclusions[p.Masked()] = true
	}
	if len(exclusions) > maxBPFExclusions {
		return fmt.Errorf("ebpf exclusion map exceeds %d entries", maxBPFExclusions)
	}
	present := uint8(1)
	for p := range exclusions {
		if err := objects.ExcludeV4.Put(prefixKey(p), present); err != nil {
			return err
		}
	}
	if len(c.Policy.Rules) > 64 {
		return fmt.Errorf("ebpf supports at most 64 rules")
	}
	nDst, nPort := 0, 0
	for index, r := range c.Policy.Rules {
		info := clientRuleInfo{Active: 1}
		if len(r.CIDRs) == 0 {
			info.AnyDst = 1
		}
		if len(r.Ports) == 0 {
			info.AnyPort = 1
		}
		id := uint32(index)
		if err := objects.Rules.Put(id, info); err != nil {
			return err
		}
		for _, p := range r.CIDRs {
			nDst++
			if nDst > maxBPFEntries {
				return fmt.Errorf("ebpf destination map exceeds %d", maxBPFEntries)
			}
			if err := objects.IncludeV4.Put(ruleKey(id, p), present); err != nil {
				return err
			}
		}
		for _, p := range r.Ports {
			nPort++
			if nPort > maxBPFEntries {
				return fmt.Errorf("ebpf port map exceeds %d", maxBPFEntries)
			}
			proto := uint8(6)
			if p.Protocol == "UDP" {
				proto = 17
			}
			if err := objects.PortRules.Put(clientPortKey{Rule: id, Port: p.Port, Proto: proto}, present); err != nil {
				return err
			}
		}
	}
	return nil
}
