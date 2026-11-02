//go:build linux

package iproute

import (
	"encoding/binary"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// wireguardGuard rejects plaintext GENEVE on every non-WG interface, including
// spoofed pod IPs arriving on eth0. Decapsulated WG packets enter IP with
// iif=rtkwg0, having passed kernel AllowedIPs source authentication.
func (b *Backend) wireguardGuard(enabled bool) error {
	conn := b.nft()
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	for _, table := range tables {
		if table.Name == "ratatoskr_wg" && table.Family == nftables.TableFamilyINet {
			conn.DelTable(table)
		}
	}
	if enabled {
		table := conn.AddTable(&nftables.Table{Name: "ratatoskr_wg", Family: nftables.TableFamilyINet})
		for _, v := range []struct {
			name  string
			hook  *nftables.ChainHook
			iface expr.MetaKey
		}{{"input", nftables.ChainHookInput, expr.MetaKeyIIFNAME}, {"output", nftables.ChainHookOutput, expr.MetaKeyOIFNAME}} {
			chain := conn.AddChain(&nftables.Chain{Name: v.name, Table: table, Type: nftables.ChainTypeFilter, Hooknum: v.hook, Priority: nftables.ChainPriorityFilter})
			rule := []expr.Any{
				&expr.Meta{Key: v.iface, Register: 1}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: append([]byte(datapath.WireGuardDevice), 0)},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, datapath.GenevePort)},
				&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop},
			}
			conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: rule})
		}
	}
	return conn.Flush()
}
