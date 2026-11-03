package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// Kubernetes may assign metadata.name to generateName after mutating but before
// validating admission. The agent, not this placeholder, authorizes the real
// Pod UID/name once scheduled. No endpoint exclusion/status trust is broadened.
func TestAgentGeneratedNameMutationSurvivesAssignedNameAndRejectsForgery(t *testing.T) {
	for _, encryption := range []string{"none", "wireguard"} {
		t.Run(encryption, func(t *testing.T) {
			ns, object := fixture()
			gw := object.(*v1alpha1.EgressGateway)
			gw.Spec.Encryption = encryption
			pod := optedPod()
			pod.Name = ""
			pod.GenerateName = "generated-client-"
			pod.Namespace = ""               // API request namespace is authoritative at CREATE.
			pod.Spec.ServiceAccountName = "" // API defaulting may add default SA later.
			h := setup(t, ns, gw)
			h.Driver = "agent"
			mutated := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
			var original datapath.ClientConfig
			if err := json.Unmarshal([]byte(mutated.Annotations[ConfigAnnotation]), &original); err != nil {
				t.Fatal(err)
			}
			if original.Identity.Namespace != "apps" || original.Identity.Pod != "" || original.Endpoint.IsValid() {
				t.Fatal("generated Pod must retain namespace but no guessed name/endpoint")
			}
			mutated.Name = "generated-client-abcde"
			mutated.Namespace = "apps"
			mutated.Spec.ServiceAccountName = "default"
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &mutated, nil)); !r.Allowed {
				t.Fatalf("valid generated Pod assigned after mutation denied: %v", r.Result)
			}
			for _, tc := range []struct {
				name  string
				forge func(*corev1.Pod)
			}{
				{"identity-pod", func(p *corev1.Pod) {
					var cfg datapath.ClientConfig
					_ = json.Unmarshal([]byte(p.Annotations[ConfigAnnotation]), &cfg)
					cfg.Identity.Pod = "forged"
					raw, _ := json.Marshal(cfg)
					p.Annotations[ConfigAnnotation] = string(raw)
				}},
				{"identity-namespace", func(p *corev1.Pod) {
					var cfg datapath.ClientConfig
					_ = json.Unmarshal([]byte(p.Annotations[ConfigAnnotation]), &cfg)
					cfg.Identity.Namespace = "forged"
					raw, _ := json.Marshal(cfg)
					p.Annotations[ConfigAnnotation] = string(raw)
				}},
				{"non-prefix-name", func(p *corev1.Pod) { p.Name = "unrelated" }},
				{"different-gateway", func(p *corev1.Pod) { p.Labels[GatewayLabel] = "other" }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					copy := mutated.DeepCopy()
					tc.forge(copy)
					if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, copy, nil)); r.Allowed {
						t.Fatal("forged generated Pod admitted")
					}
				})
			}
			// Revoking namespace authorization between mutation and validation still
			// denies, including generated Pod placeholders.
			h.Client = setup(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}}, gw).Client
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &mutated, nil)); r.Allowed {
				t.Fatal("namespace authorization revocation ignored")
			}
		})
	}
}

func TestAgentGeneratedNameStatusChurnKeepsAdmissionIntentAndRejectsPolicyForgery(t *testing.T) {
	ns, object := fixture()
	gateway := object.(*v1alpha1.EgressGateway)
	pod := optedPod()
	pod.Name = ""
	pod.GenerateName = "replicaset-child-"
	h := setup(t, ns, gateway)
	h.Driver = "agent"
	mutated := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	mutated.Name = "replicaset-child-abcde"
	gateway.Status.Endpoints = nil
	gateway.Status.EffectiveExclusions = []v1alpha1.EffectiveExclusion{{CIDR: "10.0.0.0/8"}}
	h.Client = setup(t, ns, gateway).Client
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &mutated, nil)); !r.Allowed {
		t.Fatalf("agent admission intent rejected after mutable gateway endpoint/exclusion churn: %v", r.Result)
	}
	forged := mutated.DeepCopy()
	var cfg datapath.ClientConfig
	if err := json.Unmarshal([]byte(forged.Annotations[ConfigAnnotation]), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Policy.Mode = "forged"
	bytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	forged.Annotations[ConfigAnnotation] = string(bytes)
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
		t.Fatal("forged policy accepted during gateway status churn")
	}
}

func TestClientConfigMismatchCategoriesNeverPrintIdentityValues(t *testing.T) {
	ns, gw := fixture()
	h := setup(t, ns, gw)
	h.Driver = "agent"
	pod := optedPod()
	mutated := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	for _, test := range []struct {
		field  string
		mutate func(*datapath.ClientConfig)
	}{
		{"identity-pod", func(c *datapath.ClientConfig) { c.Identity.Pod = "PRIVATE-pod-value" }},
		{"identity-namespace", func(c *datapath.ClientConfig) { c.Identity.Namespace = "PRIVATE-namespace-value" }},
		{"identity-policy", func(c *datapath.ClientConfig) { c.Identity.Policy = "PRIVATE-policy-value" }},
		{"gateway-id", func(c *datapath.ClientConfig) { c.GatewayID = 999 }},
		{"encryption", func(c *datapath.ClientConfig) { c.Encryption = "wireguard" }},
	} {
		t.Run(test.field, func(t *testing.T) {
			copy := mutated.DeepCopy()
			var cfg datapath.ClientConfig
			if err := json.Unmarshal([]byte(copy.Annotations[ConfigAnnotation]), &cfg); err != nil {
				t.Fatal(err)
			}
			test.mutate(&cfg)
			raw, _ := json.Marshal(cfg)
			copy.Annotations[ConfigAnnotation] = string(raw)
			response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, copy, nil))
			if response.Allowed || response.Result == nil || !strings.Contains(response.Result.Message, "("+test.field+")") ||
				strings.Contains(response.Result.Message, "PRIVATE-") {
				t.Fatalf("unsafe mismatch classification: %v", response.Result)
			}
		})
	}
}
