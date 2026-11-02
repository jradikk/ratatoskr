package observability

import (
	"encoding/binary"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	mdnetlink "github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func guardFixture() ([]*nftables.Chain, map[string][]*nftables.Rule) {
	table := &nftables.Table{Name: "ratatoskr_wg", Family: nftables.TableFamilyINet}
	chains := make([]*nftables.Chain, 0, 2)
	rules := make(map[string][]*nftables.Rule, 2)
	for _, name := range []string{"input", "output"} {
		hook := nftables.ChainHookInput
		iface := expr.MetaKeyIIFNAME
		if name == "output" {
			hook = nftables.ChainHookOutput
			iface = expr.MetaKeyOIFNAME
		}
		accept := nftables.ChainPolicyAccept
		chain := &nftables.Chain{Table: table, Name: name, Hooknum: hook, Priority: nftables.ChainPriorityFilter, Type: nftables.ChainTypeFilter, Policy: &accept}
		chains = append(chains, chain)
		rules[name] = []*nftables.Rule{{Table: table, Chain: chain, Handle: uint64(10 + len(chains)), Exprs: []expr.Any{
			&expr.Meta{Key: iface, Register: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: append([]byte(datapath.WireGuardDevice), 0)},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, datapath.GenevePort)},
			&expr.Counter{Packets: 3, Bytes: 128},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}}}
	}
	return chains, rules
}
func guardMetric(t *testing.T, text, name, direction, value string) {
	t.Helper()
	line := "\nratatoskr_gateway_plaintext_geneve_" + name + `{direction="` + direction + `"} ` + value + "\n"
	if strings.Count(text, line) != 1 {
		t.Fatalf("metric line %q missing or duplicated", line)
	}
}
func guardHandler(read GuardReader) http.Handler {
	return WireGuardHandler(func() (bool, int) { return true, 1320 }, NewGatewayProgramming(), NewGatewayLinkTraffic(true, nil), NewGatewayPlaintextGuard(read), "rtkwg0", func(string) (*wgtypes.Device, error) { return &wgtypes.Device{}, nil })
}
func guardScrape(t *testing.T, handler http.Handler) string {
	t.Helper()
	result := linkMetrics(t, handler)
	for _, forbidden := range []string{"10.42.1.8", "uid=", "publicKey", "rtkwg0", "{peer="} {
		if strings.Contains(result, forbidden) {
			t.Fatal("plaintext guard telemetry disclosed identity")
		}
	}
	return result
}
func TestPlaintextGuardCountersResetAndUnknown(t *testing.T) {
	chains, rules := guardFixture()
	handles := map[string]uint64{"input": rules["input"][0].Handle, "output": rules["output"][0].Handle}
	handler := guardHandler(func() ([]*nftables.Chain, map[string][]*nftables.Rule, map[string]uint64, error) {
		return chains, rules, handles, nil
	})
	first := guardScrape(t, handler)
	for _, direction := range []string{"input", "output"} {
		guardMetric(t, first, "sample_ok", direction, "1")
		guardMetric(t, first, "drop_packets", direction, "3")
		guardMetric(t, first, "drop_bytes", direction, "128")
	}
	// Counter recreation resets downwards, never rewrite as monotonic totals.
	rules["input"][0].Exprs[6] = &expr.Counter{Packets: 0, Bytes: 0}
	reset := guardScrape(t, handler)
	guardMetric(t, reset, "drop_packets", "input", "0")
	guardMetric(t, reset, "drop_bytes", "input", "0")
	// Missing one rule is unknown in that direction; no stale value survives.
	delete(rules, "input")
	unknown := guardScrape(t, handler)
	guardMetric(t, unknown, "sample_ok", "input", "0")
	guardMetric(t, unknown, "sample_ok", "output", "1")
	if strings.Contains(unknown, `ratatoskr_gateway_plaintext_geneve_drop_packets{direction="input"}`) {
		t.Fatal("unknown guard emitted stale count")
	}
	handler = guardHandler(func() ([]*nftables.Chain, map[string][]*nftables.Rule, map[string]uint64, error) {
		return nil, nil, nil, errors.New("private PodIP 10.42.1.8")
	})
	unknown = guardScrape(t, handler)
	for _, direction := range []string{"input", "output"} {
		guardMetric(t, unknown, "sample_ok", direction, "0")
	}
	if strings.Contains(unknown, "ratatoskr_gateway_plaintext_geneve_drop_packets") {
		t.Fatal("failed read exported counts")
	}
}
func TestPlaintextGuardRefusesForeignRules(t *testing.T) {
	cases := map[string]func(*nftables.Chain, *nftables.Rule){
		"wrong table":    func(c *nftables.Chain, _ *nftables.Rule) { c.Table.Name = "foreign" },
		"wrong hook":     func(c *nftables.Chain, _ *nftables.Rule) { c.Hooknum = nftables.ChainHookOutput },
		"wrong priority": func(c *nftables.Chain, _ *nftables.Rule) { c.Priority = nftables.ChainPriorityMangle },
		"wrong iface": func(_ *nftables.Chain, r *nftables.Rule) {
			r.Exprs[1] = &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte("eth0\x00")}
		},
		"wrong comparison": func(_ *nftables.Chain, r *nftables.Rule) {
			r.Exprs[1] = &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(datapath.WireGuardDevice), 0)}
		},
		"wrong protocol": func(_ *nftables.Chain, r *nftables.Rule) {
			r.Exprs[3] = &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}}
		},
		"wrong port": func(_ *nftables.Chain, r *nftables.Rule) {
			r.Exprs[5] = &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x14, 0x73}}
		},
		"wrong verdict": func(_ *nftables.Chain, r *nftables.Rule) { r.Exprs[7] = &expr.Verdict{Kind: expr.VerdictAccept} },
		"missing counter": func(_ *nftables.Chain, r *nftables.Rule) {
			r.Exprs[6] = &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}
		},
		"extra expression": func(_ *nftables.Chain, r *nftables.Rule) { r.Exprs = append(r.Exprs, &expr.Counter{}) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			chains, rules := guardFixture()
			mutate(chains[0], rules["input"][0])
			got := guardScrape(t, guardHandler(func() ([]*nftables.Chain, map[string][]*nftables.Rule, map[string]uint64, error) {
				return chains, rules, map[string]uint64{"input": rules["input"][0].Handle, "output": rules["output"][0].Handle}, nil
			}))
			guardMetric(t, got, "sample_ok", "input", "0")
			if strings.Contains(got, `ratatoskr_gateway_plaintext_geneve_drop_bytes{direction="input"}`) {
				t.Fatal("foreign rule counted as owned guard")
			}
		})
	}
}
func TestRawVerdictRequiresDropNotAccept(t *testing.T) {
	for _, verdict := range []struct {
		name string
		kind expr.VerdictKind
		want bool
	}{{"drop", expr.VerdictDrop, true}, {"accept", expr.VerdictAccept, false}} {
		t.Run(verdict.name, func(t *testing.T) {
			guard := &expr.Verdict{Kind: verdict.kind}
			encoded, err := expr.Marshal(byte(nftables.TableFamilyINet), guard)
			if err != nil {
				t.Fatal(err)
			}
			expressions := make([]mdnetlink.Attribute, 8)
			for i := 0; i < 7; i++ {
				expressions[i] = mdnetlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: []byte{}}
			}
			expressions[7] = mdnetlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: encoded}
			body, err := mdnetlink.MarshalAttributes(expressions)
			if err != nil {
				t.Fatal(err)
			}
			outer, err := mdnetlink.MarshalAttributes([]mdnetlink.Attribute{
				{Type: unix.NFTA_RULE_TABLE, Data: []byte("ratatoskr_wg\x00")},
				{Type: unix.NFTA_RULE_CHAIN, Data: []byte("input\x00")},
				{Type: unix.NFTA_RULE_HANDLE, Data: binary.BigEndian.AppendUint64(nil, 31)},
				{Type: unix.NLA_F_NESTED | unix.NFTA_RULE_EXPRESSIONS, Data: body},
			})
			if err != nil {
				t.Fatal(err)
			}
			frame := append([]byte{byte(nftables.TableFamilyINet), unix.NFNETLINK_V0, 0, 0}, outer...)
			if got := rawRuleHasDrop(frame, "input", 31); got != verdict.want {
				t.Fatalf("raw verdict %s accepted as drop=%t", verdict.name, got)
			}
			if rawRuleHasDrop(frame, "output", 31) || rawRuleHasDrop(frame, "input", 32) {
				t.Fatal("cross-chain/handle raw proof accepted")
			}
		})
	}
}

func TestPlaintextGuardTimeoutSingleReader(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	handler := guardHandler(func() ([]*nftables.Chain, map[string][]*nftables.Rule, map[string]uint64, error) {
		calls.Add(1)
		close(started)
		<-release
		chains, rules := guardFixture()
		return chains, rules, map[string]uint64{"input": rules["input"][0].Handle, "output": rules["output"][0].Handle}, nil
	})
	first := make(chan string, 1)
	go func() { first <- guardScrape(t, handler) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("guard reader did not start")
	}
	select {
	case text := <-first:
		for _, direction := range []string{"input", "output"} {
			guardMetric(t, text, "sample_ok", direction, "0")
		}
		if strings.Contains(text, "ratatoskr_gateway_plaintext_geneve_drop_packets") {
			t.Fatal("timeout exposed stale counters")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("guard scrape unbounded")
	}
	second := guardScrape(t, handler)
	if calls.Load() != 1 {
		t.Fatal("blocked reader stacked")
	}
	for _, direction := range []string{"input", "output"} {
		guardMetric(t, second, "sample_ok", direction, "0")
	}
	close(release)
}
