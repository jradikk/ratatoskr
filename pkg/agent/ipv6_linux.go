//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const ipv6GuardTable = "ratatoskr_agent_ipv6"
const quarantineTable = "ratatoskr_agent_quarantine"

var errUnsupportedIPv6 = errors.New("workload acquired unsupported IPv6; IPv4 quarantined, recreate pod")

// The IPv6 guard is present for the entire lifetime of a selected workload,
// not merely after detecting IPv6. This closes the interval between a CNI
// assigning a global IPv6 address and the agent's next reconcile. IPv4 is
// quarantined if unexpected IPv6 is observed; recovery requires pod recreation.
func ensureOutputDrop(tableName string, family nftables.TableFamily) error {
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("list nftables tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == tableName && t.Family == family {
			return verifyOutputDrop(conn, t)
		}
	}
	t := conn.AddTable(&nftables.Table{Name: tableName, Family: family})
	policy := nftables.ChainPolicyDrop
	for _, base := range []struct {
		name string
		hook *nftables.ChainHook
	}{{"output", nftables.ChainHookOutput}, {"forward", nftables.ChainHookForward}, {"input", nftables.ChainHookInput}} {
		conn.AddChain(&nftables.Chain{Name: base.name, Table: t, Type: nftables.ChainTypeFilter, Hooknum: base.hook, Priority: nftables.ChainPriorityRaw, Policy: &policy})
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("install %s drop guard: %w", tableName, err)
	}
	return verifyOutputDrop(&nftables.Conn{}, t)
}

func verifyOutputDrop(conn *nftables.Conn, t *nftables.Table) error {
	chains, err := conn.ListChains()
	if err != nil {
		return err
	}
	found := map[string]bool{}
	for _, c := range chains {
		if c.Table == nil || c.Table.Family != t.Family || c.Table.Name != t.Name {
			continue
		}
		if c.Name != "output" && c.Name != "forward" && c.Name != "input" {
			return fmt.Errorf("unexpected chain %s in %s guard", c.Name, t.Name)
		}
		hook := nftables.ChainHookOutput
		switch c.Name {
		case "forward":
			hook = nftables.ChainHookForward
		case "input":
			hook = nftables.ChainHookInput
		}
		if c.Type != nftables.ChainTypeFilter || c.Hooknum == nil || *c.Hooknum != *hook || c.Priority == nil || *c.Priority != *nftables.ChainPriorityRaw || c.Policy == nil || *c.Policy != nftables.ChainPolicyDrop || found[c.Name] {
			return fmt.Errorf("%s guard chain %s is not a raw-priority drop base chain", t.Name, c.Name)
		}
		rules, err := conn.GetRules(t, c)
		if err != nil {
			return err
		}
		if len(rules) != 0 {
			return fmt.Errorf("%s guard chain %s contains bypass rules", t.Name, c.Name)
		}
		found[c.Name] = true
	}
	if !found["output"] || !found["forward"] || !found["input"] {
		return fmt.Errorf("%s guard missing input, output, or forward drop hook", t.Name)
	}
	return nil
}

func quarantined() (bool, error) {
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	if err != nil {
		return false, err
	}
	for _, t := range tables {
		if t.Name == quarantineTable && t.Family == nftables.TableFamilyIPv4 {
			return true, verifyOutputDrop(conn, t)
		}
	}
	return false, nil
}

func globalIPv6(addrs []netlink.Addr) bool {
	for _, a := range addrs {
		if a.IP == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		if ok && ip.Is6() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
			return true
		}
	}
	return false
}

// inspectAndGuard is called only on a locked thread inside the verified pod
// network namespace, both before metadata reads and just before marker creation.
func inspectAndGuard() error {
	if err := ensureOutputDrop(ipv6GuardTable, nftables.TableFamilyIPv6); err != nil {
		return err
	}
	link, err := netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("inspect workload eth0: %w", err)
	}
	addrs, err := netlink.AddrList(link, unix.AF_INET6)
	if err != nil {
		return err
	}
	if globalIPv6(addrs) {
		if err := ensureOutputDrop(quarantineTable, nftables.TableFamilyIPv4); err != nil {
			return fmt.Errorf("dual-stack quarantine failed: %w", err)
		}
	}
	blocked, err := quarantined()
	if err != nil {
		return err
	}
	if blocked {
		return errUnsupportedIPv6
	}
	return nil
}

// guardWorkload is called on the locked target-netns thread. If inspection or
// guard installation fails, remove readiness while still in that namespace.
// An error is never treated as proof that the IPv6 deny hook is present.
func guardWorkload() error {
	if err := inspectAndGuard(); err != nil {
		return errors.Join(err, clearReadyMarker())
	}
	return nil
}

func clearReadyMarker() error {
	marker, err := netlink.LinkByName(Marker)
	if isMissingLink(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, ok := marker.(*netlink.Dummy); !ok {
		return fmt.Errorf("readiness marker is not a dummy link")
	}
	return netlink.LinkDel(marker)
}

func (r *Reconciler) setPodError(ctx context.Context, pod *corev1.Pod) error {
	if pod.Annotations[ReadyAnnotation] == "error" {
		return nil
	}
	original := pod.DeepCopy()
	pod.Annotations = copyAnnotations(pod.Annotations)
	pod.Annotations[ReadyAnnotation] = "error"
	return r.Client.Patch(ctx, pod, client.MergeFrom(original))
}

// Both guard hooks have no per-interface exemption; traffic through secondary
// interfaces must not bypass this IPv4-only gateway contract.
