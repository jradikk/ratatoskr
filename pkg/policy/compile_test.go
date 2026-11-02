package policy

import (
	"net/netip"
	"testing"

	v1alpha1 "github.com/skaldhall/ratatoskr/api/v1alpha1"
)

func TestCompile(t *testing.T) {
	end := int32(443)
	p, err := Compile(v1alpha1.EgressPolicySpec{Mode: "include", ExcludeCIDRs: []string{"10.0.0.1/8", "10.0.0.0/8"}, Rules: []v1alpha1.EgressRule{{CIDRs: []string{"203.0.113.7/24", "203.0.113.0/24"}, Ports: []v1alpha1.EgressPort{{Protocol: "TCP", Port: 441, EndPort: &end}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ExcludeCIDRs) != 1 || p.ExcludeCIDRs[0] != netip.MustParsePrefix("10.0.0.0/8") || len(p.Rules[0].CIDRs) != 1 || len(p.Rules[0].Ports) != 3 || p.Rules[0].Ports[2].Port != 443 {
		t.Fatalf("incorrect normalized selector: %+v", p)
	}
	for _, tc := range []struct {
		name string
		spec v1alpha1.EgressPolicySpec
	}{
		{"mode", v1alpha1.EgressPolicySpec{Mode: "ignored"}},
		{"IPv6", v1alpha1.EgressPolicySpec{Mode: "include", Rules: []v1alpha1.EgressRule{{CIDRs: []string{"2001:db8::/32"}}}}},
		{"invalid exclusion", v1alpha1.EgressPolicySpec{Mode: "exclude", ExcludeCIDRs: []string{"invalid"}}},
		{"protocol", v1alpha1.EgressPolicySpec{Mode: "include", Rules: []v1alpha1.EgressRule{{Ports: []v1alpha1.EgressPort{{Protocol: "SCTP", Port: 80}}}}}},
		{"range reverse", v1alpha1.EgressPolicySpec{Mode: "include", Rules: []v1alpha1.EgressRule{{Ports: []v1alpha1.EgressPort{{Protocol: "TCP", Port: 444, EndPort: &end}}}}}},
		{"range bound", v1alpha1.EgressPolicySpec{Mode: "include", Rules: []v1alpha1.EgressRule{{Ports: []v1alpha1.EgressPort{{Protocol: "TCP", Port: 1, EndPort: ptr(65535)}}}}}},
		{"crossproduct bound", v1alpha1.EgressPolicySpec{Mode: "include", Rules: []v1alpha1.EgressRule{{CIDRs: makeCIDRs(64), Ports: []v1alpha1.EgressPort{{Protocol: "UDP", Port: 1, EndPort: ptr(100)}}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Compile(tc.spec); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
func ptr(n int32) *int32 { return &n }
func makeCIDRs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, 0, byte(i)}), 32).String())
	}
	return out
}
