package webhook

import (
	"context"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
)

func TestGatewayDNSRequiresHealthyService(t *testing.T) {
	ns, gw := fixture()
	gateway := gw.(*v1alpha1.EgressGateway)
	gateway.Spec.DNS.Mode = "gateway"
	pod := optedPod()
	client := func(objects ...bool) *Handler {
		service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "gateway-dns", Namespace: "system"}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.10"}}
		if len(objects) > 0 && objects[0] {
			return setup(t, ns, gateway, service)
		}
		return setup(t, ns, gateway)
	}
	h := client()
	r := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
	if r.Allowed || !strings.Contains(r.Result.Message, "gateway DNS Service unavailable") {
		t.Fatalf("missing DNS Service accepted: %+v", r.Result)
	}
	h = client(true)
	pod.Spec.DNSConfig = &corev1.PodDNSConfig{Searches: []string{"custom.example"}}
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	if out.Spec.DNSPolicy != corev1.DNSNone || out.Spec.DNSConfig == nil || len(out.Spec.DNSConfig.Nameservers) != 1 || out.Spec.DNSConfig.Nameservers[0] != "10.96.0.10" {
		t.Fatalf("gateway DNS did not use dedicated Service IP: %+v", out.Spec.DNSConfig)
	}
	expected := []string{"apps.svc.cluster.local", "svc.cluster.local", "cluster.local", "custom.example"}
	for i, search := range expected {
		if len(out.Spec.DNSConfig.Searches) <= i || out.Spec.DNSConfig.Searches[i] != search {
			t.Fatalf("search domains: %v", out.Spec.DNSConfig.Searches)
		}
	}
	if r = h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !r.Allowed {
		t.Fatalf("valid gateway DNS config rejected: %+v", r.Result)
	}
	forged := out.DeepCopy()
	forged.Spec.DNSConfig.Nameservers = []string{"8.8.8.8"}
	if r = h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
		t.Fatal("forged node DNS fallback accepted")
	}
	invalidService := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "gateway-dns", Namespace: "system"}, Spec: corev1.ServiceSpec{ClusterIP: "None"}}
	h = setup(t, ns, gateway, invalidService)
	if r = h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)); r.Allowed || !strings.Contains(r.Result.Message, "no valid IPv4 ClusterIP") {
		t.Fatalf("invalid DNS Service ClusterIP accepted: %+v", r.Result)
	}
	gateway.Status.Endpoints = nil
	h = client(true)
	if r = h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)); r.Allowed || !strings.Contains(r.Result.Message, "healthy gateway") {
		t.Fatalf("unhealthy DNS gateway accepted: %+v", r.Result)
	}
}
func TestClusterDNSUnchanged(t *testing.T) {
	namespace, gateway := fixture()
	h := setup(t, namespace, gateway)
	pod := optedPod()
	pod.Spec.DNSPolicy = corev1.DNSDefault
	pod.Spec.DNSConfig = &corev1.PodDNSConfig{Nameservers: []string{"10.96.0.53"}, Searches: []string{"custom.example"}}
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	if out.Spec.DNSPolicy != pod.Spec.DNSPolicy || len(out.Spec.DNSConfig.Nameservers) != 1 || out.Spec.DNSConfig.Nameservers[0] != "10.96.0.53" || len(out.Spec.DNSConfig.Searches) != 1 || out.Spec.DNSConfig.Searches[0] != "custom.example" {
		t.Fatalf("cluster DNS unexpectedly changed: %+v", out.Spec.DNSConfig)
	}
}

func TestSelectorsOverlapWithoutExistingPods(t *testing.T) {
	ns, _ := fixture()
	existing := &v1alpha1.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "existing", Namespace: "apps"}, Spec: v1alpha1.EgressPolicySpec{GatewayRef: v1alpha1.GatewayReference{Name: "gateway"}, Mode: "include", WorkloadSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}}
	h := setup(t, ns, existing)
	candidate := existing.DeepCopy()
	candidate.Name = "candidate"
	candidate.Spec.WorkloadSelector = metav1.LabelSelector{MatchLabels: map[string]string{"team": "prod"}}
	r := h.Validate(context.Background(), req(t, "EgressPolicy", admissionv1.Create, candidate, nil))
	if r.Allowed || !strings.Contains(r.Result.Message, "overlaps") {
		t.Fatalf("potential overlap accepted without pods: %+v", r.Result)
	}
	candidate.Spec.WorkloadSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}
	r = h.Validate(context.Background(), req(t, "EgressPolicy", admissionv1.Create, candidate, nil))
	if !r.Allowed {
		t.Fatalf("disjoint policies rejected: %+v", r.Result)
	}
}
