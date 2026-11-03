package webhook

import (
	"context"
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func domainFixture() *v1alpha1.EgressPolicy {
	return &v1alpha1.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "domain", Namespace: "apps"}, Spec: v1alpha1.EgressPolicySpec{
		GatewayRef:       v1alpha1.GatewayReference{Name: "gateway"},
		WorkloadSelector: metav1.LabelSelector{MatchLabels: map[string]string{GatewayLabel: "gateway"}},
		Mode:             "include", Rules: []v1alpha1.EgressRule{{Domains: []v1alpha1.DomainSelector{{MatchName: "api.example.com"}, {MatchPattern: "*.example.com"}}, Ports: []v1alpha1.EgressPort{{Protocol: "TCP", Port: 443}}}},
	}}
}
func domainService() *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "gateway-dns", Namespace: "system"}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.10"}}
}
func TestDomainPolicyRequiresAgentAndGatewayDNSForPolicyAndWorkload(t *testing.T) {
	for _, mode := range []string{"include", "exclude"} {
		t.Run(mode, func(t *testing.T) {
			ns, obj := fixture()
			gateway := obj.(*v1alpha1.EgressGateway)
			pol := domainFixture()
			pol.Spec.Mode = mode
			pod := optedPod()
			pod.Spec.DNSPolicy = corev1.DNSDefault
			h := setup(t, ns, gateway, pol, domainService())
			h.Driver = "agent"
			verifyPolicy := func(accepted bool) {
				t.Helper()
				result := h.Validate(context.Background(), req(t, "EgressPolicy", admissionv1.Create, pol, nil))
				if result.Allowed != accepted {
					t.Fatalf("policy acceptance=%v: %v", result.Allowed, result.Result)
				}
			}
			verifyPod := func(accepted bool) *corev1.Pod {
				t.Helper()
				result := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
				if result.Allowed != accepted {
					t.Fatalf("pod acceptance=%v: %v", result.Allowed, result.Result)
				}
				if !accepted {
					return nil
				}
				created := mutatedPod(t, result, pod)
				if created.Spec.DNSPolicy != corev1.DNSNone || created.Spec.DNSConfig.Nameservers[0] != "10.96.0.10" {
					t.Fatal("domain Pod must use gateway DNS with no node fallback")
				}
				return &created
			}
			verifyPolicy(false)
			verifyPod(false) // cluster-mode DNS never observes selected answers.
			gateway.Spec.DNS.Mode = "gateway"
			h = setup(t, ns, gateway, pol, domainService())
			h.Driver = "init"
			verifyPolicy(false)
			verifyPod(false)
			h.Driver = "agent"
			verifyPolicy(true)
			created := verifyPod(true)
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, created, nil)); !r.Allowed {
				t.Fatalf("valid observed-DNS policy Pod rejected: %v", r.Result)
			}
			var cfg datapath.ClientConfig
			if e := json.Unmarshal([]byte(created.Annotations[ConfigAnnotation]), &cfg); e != nil {
				t.Fatal(e)
			}
			if cfg.Policy.Mode != mode || len(cfg.Policy.Rules) != 0 {
				t.Fatal("unresolved domain-only selector escaped fail-closed static policy")
			}
			forged := created.DeepCopy()
			forged.Spec.DNSConfig.Nameservers = []string{"8.8.8.8"}
			if h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)).Allowed {
				t.Fatal("forged DNS resolver bypass accepted")
			}
			gateway.Spec.DNS.Mode = "cluster"
			h = setup(t, ns, gateway, pol, domainService())
			h.Driver = "agent"
			verifyPolicy(false)
			verifyPod(false) // revoke observation before Pod admission.
		})
	}
}

func TestDomainSelectorsCanonicalNameAndPatternOnPolicyAdmission(t *testing.T) {
	ns, obj := fixture()
	gateway := obj.(*v1alpha1.EgressGateway)
	gateway.Spec.DNS.Mode = "gateway"
	h := setup(t, ns, gateway, domainService())
	h.Driver = "agent"
	for _, selectors := range [][]v1alpha1.DomainSelector{
		{{MatchName: "api.EXAMPLE.com"}}, {{MatchName: "api.example.com."}},
		{{MatchName: "https://example.com"}}, {{MatchName: "192.0.2.1"}},
		{{MatchPattern: "*.com"}}, {{MatchPattern: "*example.com"}},
		{{MatchPattern: "*.EXAMPLE.com"}}, {{MatchPattern: "*.example.com."}},
		{{MatchName: "a.example.com", MatchPattern: "*.example.com"}}, {{}},
	} {
		policy := domainFixture()
		policy.Spec.Rules[0].Domains = selectors
		result := h.Validate(context.Background(), req(t, "EgressPolicy", admissionv1.Create, policy, nil))
		if result.Allowed {
			t.Fatalf("invalid domain selector accepted: %+v", selectors)
		}
	}
}

func TestUpstreamProfilesAdmissionMutualExclusionUniqueBounded(t *testing.T) {
	ns, obj := fixture()
	gateway := obj.(*v1alpha1.EgressGateway)
	gateway.Spec.Upstream.Profiles = []v1alpha1.UpstreamProfile{{Name: "europe", SecretRef: v1alpha1.SecretReference{Name: "vpn-europe"}}, {Name: "us-west", SecretRef: v1alpha1.SecretReference{Name: "vpn-us"}}}
	admitted := func(g *v1alpha1.EgressGateway) bool {
		h := setup(t, ns, g)
		return h.Validate(context.Background(), req(t, "EgressGateway", admissionv1.Create, g, nil)).Allowed
	}
	if !admitted(gateway) {
		t.Fatal("valid independent named profiles denied")
	}
	for _, tc := range []struct {
		name   string
		change func(*v1alpha1.EgressGateway)
	}{
		{"mixed-legacy", func(g *v1alpha1.EgressGateway) { g.Spec.Upstream.SecretRef.Name = "vpn-old" }},
		{"replicas", func(g *v1alpha1.EgressGateway) { g.Spec.Replicas = 2 }},
		{"image", func(g *v1alpha1.EgressGateway) { g.Spec.Upstream.Image = "registry/override" }},
		{"duplicate", func(g *v1alpha1.EgressGateway) { g.Spec.Upstream.Profiles[1].Name = "europe" }},
		{"missing-secret", func(g *v1alpha1.EgressGateway) { g.Spec.Upstream.Profiles[1].SecretRef.Name = "" }},
		{"bad-secret", func(g *v1alpha1.EgressGateway) { g.Spec.Upstream.Profiles[1].SecretRef.Name = "vpn/other-namespace" }},
		{"bad-label", func(g *v1alpha1.EgressGateway) { g.Spec.Upstream.Profiles[1].Name = "EU" }},
		{"oversize", func(g *v1alpha1.EgressGateway) {
			g.Spec.Upstream.Profiles = append(g.Spec.Upstream.Profiles, make([]v1alpha1.UpstreamProfile, 7)...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := gateway.DeepCopy()
			tc.change(copy)
			if admitted(copy) {
				t.Fatal("invalid profile admitted")
			}
		})
	}
	// Legacy Secret-less fixtures retain controller NotReady semantics for an
	// unavailable Secret; a supplied legacy reference must never accept a path.
	legacy := gateway.DeepCopy()
	legacy.Spec.Upstream.Profiles = nil
	legacy.Spec.Upstream.SecretRef.Name = "vpn-legacy"
	if !admitted(legacy) {
		t.Fatal("legacy single Secret denied")
	}
	legacy.Spec.Upstream.SecretRef.Name = "other/ns"
	if admitted(legacy) {
		t.Fatal("cross-namespace Secret path accepted")
	}
}
