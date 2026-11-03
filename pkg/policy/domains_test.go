package policy

import (
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
)

func TestUnresolvedDomainRuleNeverBecomesWildcard(t *testing.T) {
	for _, mode := range []string{"include", "exclude"} {
		spec := api.EgressPolicySpec{Mode: mode, Rules: []api.EgressRule{{Domains: []api.DomainSelector{{MatchName: "cdn.example.com"}}, Ports: []api.EgressPort{{Protocol: "TCP", Port: 443}}}}}
		compiled, err := Compile(spec)
		if err != nil || len(compiled.Rules) != 0 {
			t.Fatalf("%s unresolved rule: %+v, %v", mode, compiled, err)
		}
		rules, err := DomainRules(spec)
		if err != nil || len(rules) != 1 || len(rules[0].Domains) != 1 || len(rules[0].Ports) != 1 {
			t.Fatalf("original rule lost: %+v %v", rules, err)
		}
	}
}

func TestDomainAndCIDRRulePreservesStaticDestination(t *testing.T) {
	spec := api.EgressPolicySpec{Mode: "exclude", Rules: []api.EgressRule{{CIDRs: []string{"203.0.113.0/24"}, Domains: []api.DomainSelector{{MatchPattern: "*.cdn.example.com"}}}, {Domains: []api.DomainSelector{{MatchName: "download.example.com"}}}}}
	compiled, err := Compile(spec)
	if err != nil || len(compiled.Rules) != 1 || compiled.Rules[0].CIDRs[0].String() != "203.0.113.0/24" {
		t.Fatalf("static CIDR lost: %+v %v", compiled, err)
	}
	rules, err := DomainRules(spec)
	if err != nil || len(rules) != 2 || len(rules[1].CIDRs) != 0 {
		t.Fatalf("original indices lost: %+v %v", rules, err)
	}
}

func TestRejectInvalidDomainSelectors(t *testing.T) {
	for _, domain := range []api.DomainSelector{{}, {MatchName: "cdn.example.com", MatchPattern: "*.example.com"}, {MatchName: "https://example.com"}, {MatchName: "EXAMPLE.com"}, {MatchName: "192.0.2.1"}, {MatchPattern: "*.com"}, {MatchPattern: "example.com"}} {
		if _, err := Compile(api.EgressPolicySpec{Mode: "include", Rules: []api.EgressRule{{Domains: []api.DomainSelector{domain}}}}); err == nil {
			t.Fatalf("invalid selector accepted: %+v", domain)
		}
	}
}
