package webhook

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAgentPlaceholderSurvivesMutableGatewayStatus(t *testing.T) {
	ns, obj := fixture()
	g := obj.(*api.EgressGateway)
	p := optedPod()
	h := setup(t, ns, g)
	h.Driver = "agent"
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, p, nil)), p)
	var initial datapath.ClientConfig
	if err := json.Unmarshal([]byte(out.Annotations[ConfigAnnotation]), &initial); err != nil {
		t.Fatal(err)
	}
	if initial.GatewayID != 42 || initial.Endpoint.IsValid() || initial.PodIP.IsValid() || initial.MTU != 0 || len(initial.Exclusions) != 0 || initial.GatewayPublicKey != "" || initial.RegistrationCACert != "" || initial.WireGuardPort != 0 || out.Annotations[ReadyAnnotation] != "pending" {
		t.Fatalf("agent persisted mutable gateway status: %+v", initial)
	}
	g.Status.Endpoints = []api.GatewayEndpoint{{PodIP: "10.2.3.5", UpstreamHealthy: true}, {PodIP: "10.2.3.6", UpstreamHealthy: false}}
	g.Status.EffectiveExclusions = []api.EffectiveExclusion{{CIDR: "192.0.2.0/24", Source: "extra"}}
	g.Status.MTU.EffectiveMTU = 900
	h = setup(t, ns, g)
	h.Driver = "agent"
	if response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !response.Allowed {
		t.Fatalf("agent placeholder rejected after status update: %+v", response.Result)
	}
	for _, change := range []struct {
		name   string
		mutate func(*datapath.ClientConfig)
	}{
		{"forged endpoint", func(c *datapath.ClientConfig) { c.Endpoint = netip.MustParseAddr("10.2.3.5") }},
		{"forged MTU", func(c *datapath.ClientConfig) { c.MTU = 900 }},
		{"forged exclusion", func(c *datapath.ClientConfig) { c.Exclusions = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			c := initial
			change.mutate(&c)
			raw, _ := json.Marshal(c)
			forged := out.DeepCopy()
			forged.Annotations[ConfigAnnotation] = string(raw)
			if response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); response.Allowed {
				t.Fatal("forged agent placeholder admitted")
			}
		})
	}
	forged := out.DeepCopy()
	forged.Annotations[ReadyAnnotation] = "true"
	if h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)).Allowed {
		t.Fatal("forged readiness admitted")
	}
	forged = out.DeepCopy()
	forged.Annotations[prefix+"agent-hash"] = "forged"
	if h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)).Allowed {
		t.Fatal("forged agent state admitted")
	}
}

func TestAgentPlaceholderDoesNotRelaxAuthorization(t *testing.T) {
	ns, obj := fixture()
	gateway := obj.(*api.EgressGateway)
	p := optedPod()
	cases := []struct {
		name   string
		change func(*api.EgressGateway, *corev1.Namespace, *corev1.Pod)
	}{
		{"namespace revoked", func(g *api.EgressGateway, n *corev1.Namespace, _ *corev1.Pod) { n.Labels["team"] = "other" }},
		{"selector removed", func(g *api.EgressGateway, _ *corev1.Namespace, _ *corev1.Pod) {
			g.Spec.AllowedNamespaces.NamespaceSelector = nil
		}},
		{"gateway ID unallocated", func(g *api.EgressGateway, _ *corev1.Namespace, _ *corev1.Pod) { g.Status.GatewayID = 0 }},
		{"unsupported upstream", func(g *api.EgressGateway, _ *corev1.Namespace, _ *corev1.Pod) { g.Spec.Upstream.Type = "custom" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := gateway.DeepCopy()
			n := ns.(*corev1.Namespace).DeepCopy()
			pod := p.DeepCopy()
			tc.change(g, n, pod)
			h := setup(t, n, g)
			h.Driver = "agent"
			if response := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)); response.Allowed {
				t.Fatal("unauthorized agent workload admitted")
			}
		})
	}
	policy := &api.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "apps"}, Spec: api.EgressPolicySpec{GatewayRef: api.GatewayReference{Name: "gateway"}, WorkloadSelector: metav1.LabelSelector{MatchLabels: map[string]string{GatewayLabel: "gateway"}}, Mode: "include"}}
	second := policy.DeepCopy()
	second.Name = "second"
	h := setup(t, ns, gateway, policy, second)
	h.Driver = "agent"
	if response := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, p, nil)); response.Allowed || !strings.Contains(response.Result.Message, "multiple EgressPolicies") {
		t.Fatalf("conflicting policy accepted: %+v", response.Result)
	}
	wrong := policy.DeepCopy()
	wrong.Spec.GatewayRef.Name = "another"
	h = setup(t, ns, gateway, wrong)
	h.Driver = "agent"
	if response := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, p, nil)); response.Allowed || !strings.Contains(response.Result.Message, "does not match selected gateway") {
		t.Fatalf("wrong gateway policy accepted: %+v", response.Result)
	}
}

func TestInitStillRejectsGatewayStatusRace(t *testing.T) {
	ns, obj := fixture()
	gateway := obj.(*api.EgressGateway)
	pod := optedPod()
	h := setup(t, ns, gateway)
	h.Driver = "init"
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	gateway.Status.Endpoints = []api.GatewayEndpoint{{PodIP: "10.2.3.5", UpstreamHealthy: true}}
	h = setup(t, ns, gateway)
	h.Driver = "init"
	if response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); response.Allowed {
		t.Fatal("init driver silently accepted endpoint mutation")
	}
}
