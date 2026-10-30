//go:build linux

package iproute

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink/nl"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func TestExclusions(t *testing.T) {
	c := datapath.ClientConfig{Endpoint: netip.MustParseAddr("10.42.2.4"), Exclusions: []netip.Prefix{netip.MustParsePrefix("10.42.8.1/16"), netip.MustParsePrefix("10.42.0.0/16")}}
	rs := exclusionRules(c)
	if len(rs) != 3 {
		t.Fatalf("got %d, expected deduplicated CIDR + endpoint + link-local", len(rs))
	}
	for i, r := range rs {
		if r.Priority != datapath.RulePriority+i || r.Table != 254 {
			t.Fatal("invalid priority/main exclusion")
		}
	}
	if r := fallback(123); r.Type != 7 || r.Priority != fallbackMetric || r.Table != 123 {
		t.Fatal("fallback must be unreachable, not throw")
	}
}
func TestIPEncap(t *testing.T) {
	e := &ipEncap{ID: 0x123456, Src: netip.MustParseAddr("10.42.1.8"), Dst: netip.MustParseAddr("10.42.2.4"), TTL: 64}
	buf, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := nl.ParseRouteAttr(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(attrs) != 5 || attrs[0].Attr.Type != 1 || binary.BigEndian.Uint64(attrs[0].Value) != e.ID {
		t.Fatal("invalid tunnel id attribute")
	}
	if len(attrs[1].Value) != 4 {
		t.Fatal("invalid destination length")
	}
	if got := netip.AddrFrom4([4]byte(attrs[1].Value)); got != e.Dst {
		t.Fatalf("dst: %s", got)
	}
	if attrs[3].Attr.Type != 4 || len(attrs[3].Value) != 1 || attrs[3].Value[0] != e.TTL {
		t.Fatal("return GENEVE needs a nonzero outer TTL")
	}
	if attrs[4].Attr.Type != 6 || binary.BigEndian.Uint16(attrs[4].Value) != 4 {
		t.Fatal("missing TUNNEL_KEY")
	}
	if !e.Equal(&ipEncap{ID: e.ID, Src: e.Src, Dst: e.Dst, TTL: e.TTL}) || e.Equal(&ipEncap{ID: e.ID, Src: e.Src, Dst: e.Dst}) {
		t.Fatal("equality must include TTL")
	}
	if _, err := (&ipEncap{ID: e.ID, Src: e.Src, Dst: e.Dst}).Encode(); err == nil {
		t.Fatal("zero outer TTL accepted")
	}
}
