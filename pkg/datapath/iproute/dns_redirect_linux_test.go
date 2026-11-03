//go:build linux

package iproute

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func fixtureDNSRule(resolver netip.Addr, proto byte) *nftables.Rule {
	ip := resolver.As4()
	return &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, DNSControlMark)},
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip[:]},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, 53)},
		&expr.Immediate{Register: 1, Data: binary.BigEndian.AppendUint16(nil, 1053)},
		&expr.Redir{RegisterProtoMin: 1},
	}}
}
func TestDNSRedirectMatchesOnlyExactResolverMarkUDPAndTCP(t *testing.T) {
	resolver := netip.MustParseAddr("10.43.1.9")
	for _, protocol := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		t.Run(string(rune(protocol)), func(t *testing.T) {
			base := fixtureDNSRule(resolver, protocol)
			if !dnsRuleMatches(base, resolver, protocol) {
				t.Fatal("fixed redirect refused")
			}
			for name, mutate := range map[string]func(*nftables.Rule){
				"other resolver": func(r *nftables.Rule) {
					r.Exprs[3] = &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 43, 1, 10}}
				},
				"other mark": func(r *nftables.Rule) {
					r.Exprs[1] = &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, 0x00400000)}
				},
				"no mark exemption": func(r *nftables.Rule) { r.Exprs = append([]expr.Any(nil), r.Exprs[1:]...) },
				"wrong dport": func(r *nftables.Rule) {
					r.Exprs[7] = &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, 5353)}
				},
				"wrong redirection": func(r *nftables.Rule) {
					r.Exprs[8] = &expr.Immediate{Register: 1, Data: binary.BigEndian.AppendUint16(nil, 8053)}
				},
				"wrong protocol": func(r *nftables.Rule) { r.Exprs[5] = &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{99}} },
			} {
				t.Run(name, func(t *testing.T) {
					copy := fixtureDNSRule(resolver, protocol)
					mutate(copy)
					if dnsRuleMatches(copy, resolver, protocol) {
						t.Fatal("foreign redirect accepted")
					}
				})
			}
		})
	}
	if DNSControlMark == 0x00100000 || DNSControlMark == 0x00200000 || DNSControlMark == 0x00400000 || DNSControlMark&0x00f00000 != DNSControlMark {
		t.Fatal("DNS mark overlaps existing owner marks or leaves reserved mask")
	}
}
