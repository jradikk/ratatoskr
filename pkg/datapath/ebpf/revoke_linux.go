//go:build linux

package ebpf

import (
	"fmt"

	cebpf "github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// revokeOldEndpoint makes updates fail closed even after an agent process
// restart, when the old tc program and maps are held by the kernel rather than
// this Backend's Go fields. It does not detach or replace any foreign filter.
func (b *Backend) revokeOldEndpoint(eth netlink.Link) error {
	filters, err := b.h.FilterList(eth, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return err
	}
	for _, f := range filters {
		bf, ok := f.(*netlink.BpfFilter)
		if !ok || f.Attrs().Priority != filterPriority || f.Attrs().Handle != filterHandle {
			continue
		}
		if bf.Name != "ratatoskr_ebpf" || !bf.DirectAction || bf.Id <= 0 || uint64(bf.Id) > uint64(^uint32(0)) {
			return fmt.Errorf("cannot revoke unrecognized tc selector")
		}
		prog, err := cebpf.NewProgramFromID(cebpf.ProgramID(bf.Id))
		if err != nil {
			return err
		}
		info, err := prog.Info()
		_ = prog.Close()
		if err != nil {
			return err
		}
		if info.Type != cebpf.SchedCLS || info.Tag != bf.Tag {
			return fmt.Errorf("tc selector identity changed before endpoint revocation")
		}
		ids, ok := info.MapIDs()
		if !ok {
			return fmt.Errorf("kernel lacks attached ebpf map IDs")
		}
		found := false
		for _, id := range ids {
			m, err := cebpf.NewMapFromID(id)
			if err != nil {
				return err
			}
			mi, err := m.Info()
			if err != nil {
				_ = m.Close()
				return err
			}
			if mi.Name == "config" {
				var config clientClientConfig
				if err := m.Lookup(uint32(0), &config); err != nil {
					_ = m.Close()
					return err
				}
				// One map update atomically replaces the old policy decision
				// with deny-all IPv4, including old CIDR/port direct passes.
				config.Mode = 3 // MODE_LOCKDOWN in bpf/client.c
				config.Healthy = 0
				config.Endpoint = 0
				config.Ifindex = 0
				if err := m.Put(uint32(0), config); err != nil {
					_ = m.Close()
					return err
				}
				found = true
			}
			_ = m.Close()
		}
		if !found {
			return fmt.Errorf("attached tc selector lacks client config map")
		}
		return nil
	}
	return nil
}
