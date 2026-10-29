package datapath

import (
	"net/netip"
	"testing"
)

func TestValidate(t *testing.T) {
	good := ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), Endpoint: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 1400, Exclusions: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*ClientConfig)
	}{
		{"zero id", func(c *ClientConfig) { c.GatewayID = 0 }}, {"large id", func(c *ClientConfig) { c.GatewayID = 1 << 24 }},
		{"ipv6", func(c *ClientConfig) { c.PodIP = netip.MustParseAddr("2001:db8::1") }}, {"small mtu", func(c *ClientConfig) { c.MTU = 575 }},
		{"encrypted", func(c *ClientConfig) { c.Encryption = "wireguard" }}, {"loop", func(c *ClientConfig) { c.Endpoint = c.PodIP }},
		{"bad exclusion", func(c *ClientConfig) { c.Exclusions = []netip.Prefix{{}} }}, {"invalid mode", func(c *ClientConfig) { c.Policy.Mode = "unknown" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.change(&c)
			if c.Validate() == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
	good.Endpoint = netip.Addr{}
	if err := good.Validate(); err != nil {
		t.Fatalf("no endpoint must be valid fail-closed config: %v", err)
	}
	gw := GatewayConfig{PodIP: netip.MustParseAddr("10.42.2.4"), GatewayID: 7, MTU: 1400, Clients: []netip.Addr{good.PodIP}}
	if err := gw.Validate(); err != nil {
		t.Fatal(err)
	}
	gw.Clients = append(gw.Clients, good.PodIP)
	if gw.Validate() == nil {
		t.Fatal("accepted duplicate client")
	}
}
func TestTable(t *testing.T) {
	if ClientTable(7) != 0x52540007 {
		t.Fatal("unexpected table")
	}
}
