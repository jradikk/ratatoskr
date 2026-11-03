package datapath

import (
	"net/netip"
	"testing"
)

func TestDomainStateValidation(t *testing.T) {
	base := ClientConfig{PodIP: netip.MustParseAddr("192.0.2.2"), GatewayID: 1, MTU: 1400, Policy: Policy{Mode: "include"}, DomainPolicyUID: "policy-uid", DomainPolicyGeneration: 1, DomainState: []DomainBinding{{Rule: 0, Address: netip.MustParseAddr("203.0.113.2"), ExpiresAt: 100, Retained: true}}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*ClientConfig)
	}{
		{"missing policy identity", func(c *ClientConfig) { c.DomainPolicyUID = ""; c.DomainPolicyGeneration = 0 }},
		{"missing generation", func(c *ClientConfig) { c.DomainPolicyGeneration = 0 }},
		{"invalid address", func(c *ClientConfig) { c.DomainState[0].Address = netip.MustParseAddr("127.0.0.1") }},
		{"wrong retention", func(c *ClientConfig) { c.DomainState[0].Retained = false }},
		{"negative index", func(c *ClientConfig) { c.DomainState[0].Rule = -1 }},
		{"index over bound", func(c *ClientConfig) { c.DomainState[0].Rule = 64 }},
		{"zero expiry", func(c *ClientConfig) { c.DomainState[0].ExpiresAt = 0 }},
		{"duplicate", func(c *ClientConfig) { c.DomainState = append(c.DomainState, c.DomainState[0]) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.DomainState = append([]DomainBinding(nil), base.DomainState...)
			tc.change(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid DNS binding accepted")
			}
		})
	}
	base.Policy.Mode = "exclude"
	base.DomainState[0].Retained = false
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
}
