package observability

import (
	"bytes"
	"context"
	"encoding/binary"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	mdnetlink "github.com/mdlayher/netlink"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// GuardReader reads one fresh kernel nftables snapshot from the gateway netns.
// Tests inject synthetic typed snapshots; no packet, peer, or workload is read.
type GuardReader func() ([]*nftables.Chain, map[string][]*nftables.Rule, map[string]uint64, error)

// KernelPlaintextGuard reads only the exact Ratatoskr-owned guard table.
// Each read uses its own nftables.Conn; links and peer identities are not read.
func KernelPlaintextGuard() ([]*nftables.Chain, map[string][]*nftables.Rule, map[string]uint64, error) {
	conn := &nftables.Conn{}
	chains, err := conn.ListChains()
	if err != nil {
		return nil, nil, nil, err
	}
	rules := make(map[string][]*nftables.Rule, 2)
	handles := make(map[string]uint64, 2)
	for _, chain := range chains {
		if chain == nil || chain.Table == nil || chain.Table.Name != "ratatoskr_wg" || chain.Table.Family != nftables.TableFamilyINet {
			continue
		}
		if chain.Name == "input" || chain.Name == "output" {
			selected, err := conn.GetRules(chain.Table, chain)
			if err != nil {
				return nil, nil, nil, err
			}
			rules[chain.Name] = selected
			if len(selected) == 1 {
				handles[chain.Name] = selected[0].Handle
			}
		}
	}
	raw, err := rawGuardVerdicts(handles)
	if err != nil {
		return nil, nil, nil, err
	}
	return chains, rules, raw, nil
}

// rawGuardVerdicts scans the original netlink rule dump to verify the terminal
// drop code. Pinned nftables v0.3.0 decodes a kernel DROP as Verdict.Kind=0,
// identical to ACCEPT, so the typed expression alone is NOT proof of a drop.
// The handle must be the same single rule returned by the typed snapshot.
func rawGuardVerdicts(handles map[string]uint64) (map[string]uint64, error) {
	out := map[string]uint64{}
	if len(handles) == 0 {
		return out, nil
	}
	conn, err := mdnetlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	for name, handle := range handles {
		if handle == 0 {
			continue
		}
		data, err := mdnetlink.MarshalAttributes([]mdnetlink.Attribute{{Type: unix.NFTA_RULE_TABLE, Data: []byte("ratatoskr_wg\x00")}, {Type: unix.NFTA_RULE_CHAIN, Data: []byte(name + "\x00")}, {Type: unix.NFTA_RULE_HANDLE, Data: binary.BigEndian.AppendUint64(nil, handle)}})
		if err != nil {
			return nil, err
		}
		msg := mdnetlink.Message{Header: mdnetlink.Header{Type: mdnetlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETRULE), Flags: mdnetlink.Request}, Data: append([]byte{byte(nftables.TableFamilyINet), unix.NFNETLINK_V0, 0, 0}, data...)}
		response, err := conn.Execute(msg)
		if err != nil {
			return nil, err
		}
		if len(response) != 1 {
			continue
		}
		if rawRuleHasDrop(response[0].Data, name, handle) {
			out[name] = handle
		}
	}
	return out, nil
}

func rawRuleHasDrop(data []byte, direction string, handle uint64) bool {
	if len(data) < 4 || data[0] != byte(nftables.TableFamilyINet) {
		return false
	}
	attrs, err := mdnetlink.UnmarshalAttributes(data[4:])
	if err != nil {
		return false
	}
	tableOK, chainOK, handleOK := false, false, false
	var expressions []mdnetlink.Attribute
	for _, a := range attrs {
		switch a.Type & 0x3fff {
		case unix.NFTA_RULE_TABLE:
			tableOK = string(bytes.TrimRight(a.Data, "\x00")) == "ratatoskr_wg"
		case unix.NFTA_RULE_CHAIN:
			chainOK = string(bytes.TrimRight(a.Data, "\x00")) == direction
		case unix.NFTA_RULE_HANDLE:
			handleOK = len(a.Data) == 8 && binary.BigEndian.Uint64(a.Data) == handle
		case unix.NFTA_RULE_EXPRESSIONS:
			expressions, err = mdnetlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return false
			}
		}
	}
	if !tableOK || !chainOK || !handleOK || len(expressions) != 8 {
		return false
	}
	last, err := mdnetlink.UnmarshalAttributes(expressions[7].Data)
	if err != nil {
		return false
	}
	nameOK := false
	var immediate []mdnetlink.Attribute
	for _, a := range last {
		switch a.Type & 0x3fff {
		case unix.NFTA_EXPR_NAME:
			nameOK = string(bytes.TrimRight(a.Data, "\x00")) == "immediate"
		case unix.NFTA_EXPR_DATA:
			immediate, err = mdnetlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return false
			}
		}
	}
	if !nameOK {
		return false
	}
	regOK := false
	var nested []mdnetlink.Attribute
	for _, a := range immediate {
		switch a.Type & 0x3fff {
		case unix.NFTA_IMMEDIATE_DREG:
			regOK = len(a.Data) == 4 && binary.BigEndian.Uint32(a.Data) == unix.NFT_REG_VERDICT
		case unix.NFTA_IMMEDIATE_DATA:
			nested, err = mdnetlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return false
			}
		}
	}
	if !regOK || len(nested) != 1 || nested[0].Type&0x3fff != unix.NFTA_DATA_VERDICT {
		return false
	}
	verdict, err := mdnetlink.UnmarshalAttributes(nested[0].Data)
	if err != nil {
		return false
	}
	if len(verdict) != 1 || verdict[0].Type&0x3fff != unix.NFTA_VERDICT_CODE || len(verdict[0].Data) != 4 {
		return false
	}
	return int32(binary.BigEndian.Uint32(verdict[0].Data)) == int32(expr.VerdictDrop)
}

type guardCounts struct{ packets, bytes uint64 }
type guardResult struct{ counts [2]*guardCounts }

// GatewayPlaintextGuard collects two resettable nftables drop counters with
// fixed direction labels only. Reinstalling the firewall resets these gauges;
// never interpret them as process-lifetime totals or a flow count.
type GatewayPlaintextGuard struct {
	read GuardReader
	sem  chan struct{}
}

func NewGatewayPlaintextGuard(read GuardReader) *GatewayPlaintextGuard {
	return &GatewayPlaintextGuard{read: read, sem: make(chan struct{}, 1)}
}

var (
	guardSampleOK = prometheus.NewDesc("ratatoskr_gateway_plaintext_geneve_sample_ok", "1 if the exact installed plaintext GENEVE guard was sampled; 0 if absent, malformed, or timed out.", []string{"direction"}, nil)
	guardPackets  = prometheus.NewDesc("ratatoskr_gateway_plaintext_geneve_drop_packets", "Current kernel plaintext GENEVE guard drops in packets (resettable gauge).", []string{"direction"}, nil)
	guardBytes    = prometheus.NewDesc("ratatoskr_gateway_plaintext_geneve_drop_bytes", "Current kernel plaintext GENEVE guard drops in bytes (resettable gauge).", []string{"direction"}, nil)
)

func (c *GatewayPlaintextGuard) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{guardSampleOK, guardPackets, guardBytes} {
		ch <- desc
	}
}

func exactGuardRule(rule *nftables.Rule, direction string, rawVerdict uint64) *guardCounts {
	if rule == nil || len(rule.Exprs) != 8 || (rule.Table != nil && (rule.Table.Name != "ratatoskr_wg" || rule.Table.Family != nftables.TableFamilyINet)) || (rule.Chain != nil && rule.Chain.Name != direction) {
		return nil
	}
	iface := expr.MetaKeyIIFNAME
	if direction == "output" {
		iface = expr.MetaKeyOIFNAME
	}
	first, ok := rule.Exprs[0].(*expr.Meta)
	if !ok || first.SourceRegister || first.Key != iface || first.Register != 1 {
		return nil
	}
	cmp, ok := rule.Exprs[1].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpNeq || cmp.Register != 1 || !bytes.Equal(cmp.Data, append([]byte(datapath.WireGuardDevice), 0)) {
		return nil
	}
	proto, ok := rule.Exprs[2].(*expr.Meta)
	if !ok || proto.SourceRegister || proto.Key != expr.MetaKeyL4PROTO || proto.Register != 1 {
		return nil
	}
	cmp, ok = rule.Exprs[3].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq || cmp.Register != 1 || !bytes.Equal(cmp.Data, []byte{unix.IPPROTO_UDP}) {
		return nil
	}
	port, ok := rule.Exprs[4].(*expr.Payload)
	if !ok || port.OperationType != expr.PayloadLoad || port.Base != expr.PayloadBaseTransportHeader || port.Offset != 2 || port.Len != 2 || port.DestRegister != 1 {
		return nil
	}
	cmp, ok = rule.Exprs[5].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq || cmp.Register != 1 || !bytes.Equal(cmp.Data, binary.BigEndian.AppendUint16(nil, datapath.GenevePort)) {
		return nil
	}
	counter, ok := rule.Exprs[6].(*expr.Counter)
	if !ok {
		return nil
	}
	verdict, ok := rule.Exprs[7].(*expr.Verdict)
	// The pinned nftables decoder reports DROP and ACCEPT as Kind=0 from
	// kernel GETRULE. A separately decoded raw signed verdict for this exact
	// handle is authoritative; synthetic tests also reject a typed ACCEPT.
	if !ok || rawVerdict == 0 || rule.Handle != rawVerdict || verdict.Chain != "" || verdict.Kind != 0 && verdict.Kind != expr.VerdictDrop {
		return nil
	}
	return &guardCounts{packets: counter.Packets, bytes: counter.Bytes}
}

func (c *GatewayPlaintextGuard) readBoth() guardResult {
	var result guardResult
	if c.read == nil {
		return result
	}
	chains, rules, verdicts, err := c.read()
	if err != nil {
		return result
	}
	seen := make(map[string]bool, 2)
	for _, chain := range chains {
		if chain == nil || chain.Table == nil || chain.Table.Name != "ratatoskr_wg" || chain.Table.Family != nftables.TableFamilyINet {
			continue
		}
		if chain.Name != "input" && chain.Name != "output" {
			return guardResult{}
		}
		if seen[chain.Name] {
			return guardResult{}
		}
		seen[chain.Name] = true
		hook := nftables.ChainHookInput
		if chain.Name == "output" {
			hook = nftables.ChainHookOutput
		}
		if chain.Type != nftables.ChainTypeFilter || chain.Hooknum == nil || *chain.Hooknum != *hook || chain.Priority == nil || *chain.Priority != *nftables.ChainPriorityFilter || chain.Policy != nil || chain.Device != "" {
			continue
		}
		selected, ok := rules[chain.Name]
		if !ok || len(selected) != 1 {
			continue
		}
		index := 0
		if chain.Name == "output" {
			index = 1
		}
		result.counts[index] = exactGuardRule(selected[0], chain.Name, verdicts[chain.Name])
	}
	return result
}

func (c *GatewayPlaintextGuard) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	emit := func(sample guardResult) {
		for i, direction := range []string{"input", "output"} {
			count := sample.counts[i]
			if count == nil || ctx.Err() != nil {
				ch <- prometheus.MustNewConstMetric(guardSampleOK, prometheus.GaugeValue, 0, direction)
				continue
			}
			ch <- prometheus.MustNewConstMetric(guardSampleOK, prometheus.GaugeValue, 1, direction)
			ch <- prometheus.MustNewConstMetric(guardPackets, prometheus.GaugeValue, float64(count.packets), direction)
			ch <- prometheus.MustNewConstMetric(guardBytes, prometheus.GaugeValue, float64(count.bytes), direction)
		}
	}
	select {
	case c.sem <- struct{}{}:
		// Netfilter has no cancellable read: preserve one worker until it exits.
		finished := make(chan guardResult, 1)
		go func() { result := c.readBoth(); finished <- result; <-c.sem }()
		select {
		case result := <-finished:
			emit(result)
		case <-ctx.Done():
			emit(guardResult{})
		}
	case <-ctx.Done():
		emit(guardResult{})
	}
}

var _ prometheus.Collector = (*GatewayPlaintextGuard)(nil)
