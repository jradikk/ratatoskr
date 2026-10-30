//go:build linux

package ebpf

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	guardPriority uint16 = filterPriority - 1
	guardHandle   uint32 = 0x52540002
)

func isOwnedUpdateGuard(f netlink.Filter) bool {
	if f.Attrs().Priority != guardPriority || f.Attrs().Handle != guardHandle || f.Attrs().Protocol != unix.ETH_P_ALL {
		return false
	}
	match, ok := f.(*netlink.MatchAll)
	if !ok || len(match.Actions) != 1 {
		return false
	}
	a, ok := match.Actions[0].(*netlink.GenericAction)
	return ok && a.Attrs().Action == netlink.TC_ACT_SHOT
}
func (b *Backend) findUpdateGuard(eth netlink.Link) (netlink.Filter, error) {
	filters, err := b.h.FilterList(eth, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return nil, err
	}
	var guard netlink.Filter
	for _, f := range filters {
		if f.Attrs().Priority != guardPriority {
			continue
		}
		if !isOwnedUpdateGuard(f) {
			return nil, fmt.Errorf("tc egress update guard priority %d occupied by foreign filter", guardPriority)
		}
		if guard != nil {
			return nil, fmt.Errorf("duplicate ebpf update guards")
		}
		guard = f
	}
	return guard, nil
}
func (b *Backend) installUpdateGuard(eth netlink.Link) error {
	q := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: eth.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}}
	if err := b.h.QdiscAdd(q); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	if err := b.checkEgressFilters(eth); err != nil {
		return err
	}
	if old, err := b.findUpdateGuard(eth); err != nil {
		return err
	} else if old != nil {
		return nil
	} // retained fail-close after prior update failure
	guard := &netlink.MatchAll{FilterAttrs: netlink.FilterAttrs{LinkIndex: eth.Attrs().Index, Parent: netlink.HANDLE_MIN_EGRESS, Priority: guardPriority, Handle: guardHandle, Protocol: unix.ETH_P_ALL}, Actions: []netlink.Action{&netlink.GenericAction{ActionAttrs: netlink.ActionAttrs{Action: netlink.TC_ACT_SHOT}}}}
	if err := b.h.FilterAdd(guard); err != nil {
		return fmt.Errorf("install ebpf update guard: %w", err)
	}
	if _, err := b.findUpdateGuard(eth); err != nil {
		return err
	}
	return nil
}
func (b *Backend) removeUpdateGuard(eth netlink.Link) error {
	guard, err := b.findUpdateGuard(eth)
	if err != nil {
		return err
	}
	if guard == nil {
		return nil
	}
	return b.h.FilterDel(guard)
}
