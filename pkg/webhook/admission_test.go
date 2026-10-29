package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func setup(t *testing.T, objects ...client.Object) *Handler {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return &Handler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build(), Namespace: "system", InitImage: "ratatoskr:init"}
}
func fixture() (client.Object, client.Object) {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps", Labels: map[string]string{"team": "alpha"}}}, &v1alpha1.EgressGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "system"}, Spec: v1alpha1.EgressGatewaySpec{Upstream: v1alpha1.UpstreamSpec{Type: "openvpn"}, AllowedNamespaces: v1alpha1.AllowedNamespacesSpec{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "alpha"}}}}, Status: v1alpha1.EgressGatewayStatus{GatewayID: 42, Endpoints: []v1alpha1.GatewayEndpoint{{PodIP: "10.2.3.4", UpstreamHealthy: true}}}}
}
func req(t *testing.T, kind string, operation admissionv1.Operation, object interface{}, old interface{}) admission.Request {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var oldRaw []byte
	if old != nil {
		oldRaw, err = json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Namespace: "apps", Kind: metav1.GroupVersionKind{Group: v1alpha1.GroupName, Version: "v1alpha1", Kind: kind}, Operation: operation, Object: runtime.RawExtension{Raw: raw}, OldObject: runtime.RawExtension{Raw: oldRaw}}}
}
func optedPod() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "apps", Labels: map[string]string{GatewayLabel: "gateway"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app"}}}}
}
func mutatedPod(t *testing.T, response admission.Response, original interface{}) corev1.Pod {
	t.Helper()
	if !response.Allowed {
		t.Fatalf("admission denied: %v", response.Result)
	}
	patches, err := json.Marshal(response.Patches)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := jsonpatch.DecodePatch(patches)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	out, err := patch.Apply(raw)
	if err != nil {
		t.Fatal(err)
	}
	var pod corev1.Pod
	if err = json.Unmarshal(out, &pod); err != nil {
		t.Fatal(err)
	}
	return pod
}
func TestMutatePodFailClosed(t *testing.T) {
	ns, g := fixture()
	h := setup(t, ns, g)
	pod := optedPod()
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	if out.Annotations[ReadyAnnotation] != "pending" {
		t.Fatalf("premature readiness: %q", out.Annotations[ReadyAnnotation])
	}
	if len(out.Spec.InitContainers) != 1 || out.Spec.InitContainers[0].SecurityContext == nil || out.Spec.InitContainers[0].SecurityContext.Capabilities.Add[0] != "NET_ADMIN" {
		t.Fatalf("missing init NET_ADMIN: %+v", out.Spec.InitContainers)
	}
	if out.Spec.InitContainers[0].Args[0] != "-config=/var/run/ratatoskr/client.json" {
		t.Fatal("wrong init argument")
	}
	var cfg datapath.ClientConfig
	if err := json.Unmarshal([]byte(out.Annotations[ConfigAnnotation]), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.GatewayID != 42 || cfg.Endpoint.String() != "10.2.3.4" || cfg.PodIP.IsValid() || cfg.MTU != 0 {
		t.Fatalf("incorrect admission-time config: %+v", cfg)
	}
	gateway := g.(*v1alpha1.EgressGateway)
	gateway.Status.Endpoints = nil
	h = setup(t, ns, gateway)
	out = mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	if err := json.Unmarshal([]byte(out.Annotations[ConfigAnnotation]), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint.IsValid() {
		t.Fatalf("unhealthy gateway unexpectedly selected: %+v", cfg)
	}
}
func TestPodDenials(t *testing.T) {
	ns, g := fixture()
	cases := []struct {
		name   string
		change func(*v1alpha1.EgressGateway, *corev1.Namespace)
		match  string
	}{
		{"unallocated", func(g *v1alpha1.EgressGateway, _ *corev1.Namespace) { g.Status.GatewayID = 0 }, "gatewayID"},
		{"disallowed", func(_ *v1alpha1.EgressGateway, n *corev1.Namespace) { n.Labels["team"] = "other" }, "not allowed"},
		{"nil selector", func(g *v1alpha1.EgressGateway, _ *corev1.Namespace) { g.Spec.AllowedNamespaces.NamespaceSelector = nil }, "denies all"},
		{"encryption", func(g *v1alpha1.EgressGateway, _ *corev1.Namespace) { g.Spec.Encryption = "wireguard" }, "not implemented"},
		{"dns", func(g *v1alpha1.EgressGateway, _ *corev1.Namespace) { g.Spec.DNS.Mode = "gateway" }, "not implemented"},
		{"upstream", func(g *v1alpha1.EgressGateway, _ *corev1.Namespace) { g.Spec.Upstream.Type = "custom" }, "not implemented"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gateway := g.(*v1alpha1.EgressGateway).DeepCopy()
			namespace := ns.(*corev1.Namespace).DeepCopy()
			tc.change(gateway, namespace)
			h := setup(t, namespace, gateway)
			r := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, optedPod(), nil))
			if r.Allowed || !strings.Contains(r.Result.Message, tc.match) {
				t.Fatalf("expected %s denial: %+v", tc.match, r.Result)
			}
		})
	}
}
func TestPolicyMatchesDenied(t *testing.T) {
	ns, g := fixture()
	p := &v1alpha1.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "apps"}, Spec: v1alpha1.EgressPolicySpec{WorkloadSelector: metav1.LabelSelector{MatchLabels: map[string]string{GatewayLabel: "gateway"}}}}
	h := setup(t, ns, g, p)
	r := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, optedPod(), nil))
	if r.Allowed || !strings.Contains(r.Result.Message, "require M3") {
		t.Fatalf("policy ignored: %+v", r.Result)
	}
	p2 := p.DeepCopy()
	p2.Name = "policy2"
	h = setup(t, ns, g, p, p2)
	r = h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, optedPod(), nil))
	if r.Allowed || !strings.Contains(r.Result.Message, "multiple EgressPolicies") {
		t.Fatalf("multiple matches not explicit: %+v", r.Result)
	}
}
func TestValidateRunningPodImmutable(t *testing.T) {
	h := setup(t)
	old := optedPod()
	old.Status.Phase = corev1.PodRunning
	newPod := old.DeepCopy()
	delete(newPod.Labels, GatewayLabel)
	r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Update, newPod, old))
	if r.Allowed {
		t.Fatal("running gateway label removed")
	}
	newPod = old.DeepCopy()
	newPod.Annotations = map[string]string{GatewayNamespace: "other"}
	r = h.Validate(context.Background(), req(t, "Pod", admissionv1.Update, newPod, old))
	if r.Allowed {
		t.Fatal("running gateway namespace changed")
	}
}
func TestPolicyOverlapAndGatewaySelector(t *testing.T) {
	ns, g := fixture()
	existing := &v1alpha1.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "existing", Namespace: "apps"}, Spec: v1alpha1.EgressPolicySpec{WorkloadSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}}}}
	pod := optedPod()
	pod.Labels["app"] = "test"
	h := setup(t, ns, g, existing, pod)
	next := existing.DeepCopy()
	next.Name = "next"
	r := h.Validate(context.Background(), req(t, "EgressPolicy", admissionv1.Create, next, nil))
	if r.Allowed || !strings.Contains(r.Result.Message, "overlaps") {
		t.Fatalf("overlap not rejected: %+v", r.Result)
	}
	gateway := g.(*v1alpha1.EgressGateway).DeepCopy()
	gateway.Spec.AllowedNamespaces.NamespaceSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "a", Operator: "Bogus"}}}
	r = h.Validate(context.Background(), req(t, "EgressGateway", admissionv1.Update, gateway, g))
	if r.Allowed {
		t.Fatal("invalid namespace selector accepted")
	}
}
