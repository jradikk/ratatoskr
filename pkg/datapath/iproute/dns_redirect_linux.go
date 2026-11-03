//go:build linux

package iproute

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// DNSControlMark is reserved for the agent's marked upstream DNS sockets.
// It is distinct from the existing probe, steering and WireGuard marks. The
// redirect ignores marked traffic to avoid the proxy feeding itself.
const DNSControlMark uint32 = 0x00800000
const dnsRedirectTable = "ratatoskr_dns_agent"
const dnsRedirectPort uint16 = 1053

// InstallDNSRedirect owns a separate IPv4 NAT OUTPUT table, independent of
// clientFirewall's ratatoskr_route replacement. It must run inside a verified
// workload netns AFTER listeners on loopback:1053 are ready. No DNS redirect
// is installed for an unverified resolver or a namespace with foreign rules.
func InstallDNSRedirect(resolver netip.Addr) error {
	if !resolver.Is4() || resolver.IsUnspecified() || resolver.IsMulticast() || resolver.IsLoopback() || resolver.IsLinkLocalUnicast() {
		return errors.New("trusted IPv4 gateway DNS Service required")
	}
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	for _, old := range tables {
		if old.Name != dnsRedirectTable {
			continue
		}
		if old.Family != nftables.TableFamilyIPv4 {
			return errors.New("foreign DNS table family")
		}
		return VerifyDNSRedirect(resolver)
	}
	table := conn.AddTable(&nftables.Table{Name: dnsRedirectTable, Family: nftables.TableFamilyIPv4})
	chain := conn.AddChain(&nftables.Chain{Name: "output", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest})
	for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		addr := resolver.As4()
		rule := []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, DNSControlMark)},
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr[:]},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, 53)},
			&expr.Immediate{Register: 1, Data: binary.BigEndian.AppendUint16(nil, dnsRedirectPort)},
			&expr.Redir{RegisterProtoMin: 1},
		}
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: rule})
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("install owned DNS interception: %w", err)
	}
	return VerifyDNSRedirect(resolver)
}

// VerifyDNSRedirect refuses an existing table with extra chains/rules or a
// different resolver. A marker alone cannot establish DNS interception.
func VerifyDNSRedirect(resolver netip.Addr) error {
	if !resolver.Is4() || resolver.IsUnspecified() || resolver.IsMulticast() || resolver.IsLoopback() {
		return errors.New("invalid DNS resolver")
	}
	conn := &nftables.Conn{}
	chains, err := conn.ListChains()
	if err != nil {
		return err
	}
	var selected *nftables.Chain
	for _, chain := range chains {
		if chain.Table == nil || chain.Table.Name != dnsRedirectTable {
			continue
		}
		if selected != nil || chain.Table.Family != nftables.TableFamilyIPv4 || chain.Name != "output" ||
			chain.Type != nftables.ChainTypeNAT || chain.Hooknum == nil || *chain.Hooknum != *nftables.ChainHookOutput ||
			chain.Priority == nil || *chain.Priority != *nftables.ChainPriorityNATDest {
			return errors.New("foreign DNS interception chain")
		}
		selected = chain
	}
	if selected == nil {
		return errors.New("DNS interception missing")
	}
	rules, err := conn.GetRules(selected.Table, selected)
	if err != nil {
		return err
	}
	if len(rules) != 2 {
		return errors.New("DNS interception rule count invalid")
	}
	for i, rule := range rules {
		if !dnsRuleMatches(rule, resolver, []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP}[i]) {
			return errors.New("DNS interception rule not owned")
		}
	}
	return nil
}

func dnsRuleMatches(rule *nftables.Rule, resolver netip.Addr, proto byte) bool {
	if rule == nil || len(rule.Exprs) != 10 || !resolver.Is4() {
		return false
	}
	mark, ok := rule.Exprs[0].(*expr.Meta)
	if !ok || mark.Key != expr.MetaKeyMARK || mark.Register != 1 || mark.SourceRegister {
		return false
	}
	cmp, ok := rule.Exprs[1].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpNeq || cmp.Register != 1 || len(cmp.Data) != 4 || binary.NativeEndian.Uint32(cmp.Data) != DNSControlMark {
		return false
	}
	address, ok := rule.Exprs[2].(*expr.Payload)
	if !ok || address.Base != expr.PayloadBaseNetworkHeader || address.Offset != 16 || address.Len != 4 || address.DestRegister != 1 {
		return false
	}
	cmp, ok = rule.Exprs[3].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq || cmp.Register != 1 || string(cmp.Data) != string(resolver.AsSlice()) {
		return false
	}
	protocol, ok := rule.Exprs[4].(*expr.Meta)
	if !ok || protocol.Key != expr.MetaKeyL4PROTO || protocol.Register != 1 || protocol.SourceRegister {
		return false
	}
	cmp, ok = rule.Exprs[5].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq || cmp.Register != 1 || len(cmp.Data) != 1 || cmp.Data[0] != proto {
		return false
	}
	port, ok := rule.Exprs[6].(*expr.Payload)
	if !ok || port.Base != expr.PayloadBaseTransportHeader || port.Offset != 2 || port.Len != 2 || port.DestRegister != 1 {
		return false
	}
	cmp, ok = rule.Exprs[7].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq || cmp.Register != 1 || len(cmp.Data) != 2 || binary.BigEndian.Uint16(cmp.Data) != 53 {
		return false
	}
	immediate, ok := rule.Exprs[8].(*expr.Immediate)
	if !ok || immediate.Register != 1 || len(immediate.Data) != 2 || binary.BigEndian.Uint16(immediate.Data) != dnsRedirectPort {
		return false
	}
	redir, ok := rule.Exprs[9].(*expr.Redir)
	return ok && redir.RegisterProtoMin == 1
}

// RemoveDNSRedirect deletes only the exact previously verified owned table.
// Unknown or modified tables are never removed by name alone.
func RemoveDNSRedirect(resolver netip.Addr) error {
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	for _, table := range tables {
		if table.Name != dnsRedirectTable {
			continue
		}
		if err := VerifyDNSRedirect(resolver); err != nil {
			return err
		}
		conn.DelTable(table)
		return conn.Flush()
	}
	return nil
}
