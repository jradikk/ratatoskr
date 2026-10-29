// Package policy validates and compiles API destination selectors into the
// CNI-independent datapath representation. Workload/DNS resolution is external.
package policy

import (
	"fmt"
	"net/netip"
	"sort"

	v1alpha1 "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// Compile rejects unsupported/malformed input instead of broadening selectors.
// A bounded expansion preserves port ranges without changing the datapath API.
func Compile(spec v1alpha1.EgressPolicySpec) (datapath.Policy, error) {
	p := datapath.Policy{Mode: spec.Mode}
	if p.Mode != "include" && p.Mode != "exclude" {
		return p, fmt.Errorf("unsupported policy mode %q", p.Mode)
	}
	var err error
	if p.ExcludeCIDRs, err = cidrs(spec.ExcludeCIDRs); err != nil {
		return p, fmt.Errorf("excludeCIDRs: %w", err)
	}
	if len(spec.Rules) > 64 || len(spec.ExcludeCIDRs) > 64 {
		return p, fmt.Errorf("policy exceeds 64 rules or exclusions")
	}
	for i, r := range spec.Rules {
		if len(r.CIDRs) > 64 || len(r.Ports) > 64 {
			return p, fmt.Errorf("rule %d exceeds 64 CIDRs or ports", i)
		}
		out := datapath.Rule{}
		if out.CIDRs, err = cidrs(r.CIDRs); err != nil {
			return p, fmt.Errorf("rule %d: %w", i, err)
		}
		seen := map[datapath.Port]bool{}
		for _, port := range r.Ports {
			if port.Protocol != "TCP" && port.Protocol != "UDP" {
				return p, fmt.Errorf("rule %d: unsupported protocol %q", i, port.Protocol)
			}
			end := port.Port
			if port.EndPort != nil {
				end = *port.EndPort
			}
			if port.Port < 1 || end < port.Port || end > 65535 {
				return p, fmt.Errorf("rule %d: invalid port range %d..%d", i, port.Port, end)
			}
			if end-port.Port+1 > 4096 {
				return p, fmt.Errorf("rule %d: port range exceeds 4096 entries", i)
			}
			for n := port.Port; n <= end; n++ {
				v := datapath.Port{Protocol: port.Protocol, Port: uint16(n)} // #nosec G115 -- n is validated in [1,65535] before the bounded loop.
				if !seen[v] {
					seen[v] = true
					out.Ports = append(out.Ports, v)
				}
			}
		}
		sort.Slice(out.Ports, func(i, j int) bool {
			if out.Ports[i].Protocol == out.Ports[j].Protocol {
				return out.Ports[i].Port < out.Ports[j].Port
			}
			return out.Ports[i].Protocol < out.Ports[j].Protocol
		})
		p.Rules = append(p.Rules, out)
	}
	// Validate also enforces the total nft rule expansion bound.
	c := datapath.ClientConfig{PodIP: netip.MustParseAddr("192.0.2.1"), GatewayID: 1, MTU: 1400, Policy: p}
	if err := c.Validate(); err != nil {
		return p, err
	}
	return p, nil
}
func cidrs(in []string) ([]netip.Prefix, error) {
	set := map[netip.Prefix]bool{}
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("invalid IPv4 CIDR %q", s)
		}
		set[p.Masked()] = true
	}
	out := make([]netip.Prefix, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}
