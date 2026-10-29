package webhook

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
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
	return &Handler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build(), Namespace: "system", InitImage: "ratatoskr:init", ClusterDomain: "cluster.local"}
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
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !r.Allowed {
		t.Fatalf("fail-closed missing endpoint config rejected: %+v", r.Result)
	}
	cfg.Endpoint = netip.MustParseAddr("10.9.9.9")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out.Annotations[ConfigAnnotation] = string(raw)
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); r.Allowed {
		t.Fatal("forged endpoint accepted when gateway has no healthy endpoint")
	}
}
func TestProgrammingInitDatapathCapabilitiesAndEnv(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		wantCaps   []corev1.Capability
	}{
		{"default iproute", "", []corev1.Capability{"NET_ADMIN"}},
		{"explicit iproute", "iproute", []corev1.Capability{"NET_ADMIN"}},
		{"ebpf", "ebpf", []corev1.Capability{"NET_ADMIN", "BPF", "PERFMON"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			namespace, gateway := fixture()
			h := setup(t, namespace, gateway)
			h.Datapath = tc.mode
			pod := optedPod()
			out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
			init := out.Spec.InitContainers[0]
			if init.SecurityContext == nil || init.SecurityContext.Capabilities == nil || !slices.Equal(init.SecurityContext.Capabilities.Add, tc.wantCaps) || len(init.SecurityContext.Capabilities.Drop) != 0 || len(init.VolumeMounts) != 1 || len(out.Spec.Volumes) != 1 {
				t.Fatalf("unexpected datapath capabilities or host mounts: %+v", init)
			}
			mode := tc.mode
			if mode == "" {
				mode = "iproute"
			}
			found := false
			for _, env := range init.Env {
				if env.Name == "DATAPATH" {
					found = true
					if env.Value != mode || env.ValueFrom != nil {
						t.Fatalf("incorrect DATAPATH env: %+v", env)
					}
				}
			}
			if !found {
				t.Fatal("DATAPATH env absent")
			}
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !r.Allowed {
				t.Fatalf("injected init rejected: %+v", r.Result)
			}
			if mode == "ebpf" {
				forged := out.DeepCopy()
				forged.Spec.InitContainers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_ADMIN"}
				if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
					t.Fatal("ebpf init without BPF/PERFMON accepted")
				}
				forged = out.DeepCopy()
				forged.Spec.InitContainers[0].Env[len(forged.Spec.InitContainers[0].Env)-1].Value = "iproute"
				if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
					t.Fatal("incorrect DATAPATH env accepted")
				}
			}
		})
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
		{"encryption", func(g *v1alpha1.EgressGateway, _ *corev1.Namespace) { g.Spec.Encryption = "invalid" }, "unsupported"},
		{"dns", func(g *v1alpha1.EgressGateway, _ *corev1.Namespace) { g.Spec.DNS.Mode = "unknown" }, "unsupported"},
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
func TestValidatePodCreateRequiresAuthorizedMutation(t *testing.T) {
	namespace, gateway := fixture()
	h := setup(t, namespace, gateway)
	pod := optedPod()
	unmutated := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
	if unmutated.Allowed || !strings.Contains(unmutated.Result.Message, "lacks safe Ratatoskr mutation") {
		t.Fatalf("opted-in Pod without mutator was allowed: %+v", unmutated.Result)
	}
	unlabeled := pod.DeepCopy()
	delete(unlabeled.Labels, GatewayLabel)
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, unlabeled, nil)); !r.Allowed {
		t.Fatalf("unlabeled Pod rejected: %+v", r.Result)
	}
	injected := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &injected, nil)); !r.Allowed {
		t.Fatalf("genuine mutated Pod rejected: %+v", r.Result)
	}
	forged := injected.DeepCopy()
	var cfg datapath.ClientConfig
	if err := json.Unmarshal([]byte(forged.Annotations[ConfigAnnotation]), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Endpoint = netip.MustParseAddr("10.9.9.9")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	forged.Annotations[ConfigAnnotation] = string(raw)
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed || !strings.Contains(r.Result.Message, "differs from authorized gateway status") {
		t.Fatalf("forged endpoint accepted: %+v", r.Result)
	}
	forged = injected.DeepCopy()
	forged.Annotations[ReadyAnnotation] = "true"
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
		t.Fatal("premature datapath readiness accepted")
	}
	forged = injected.DeepCopy()
	forged.Spec.InitContainers[0].Image = "user-controlled:init"
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
		t.Fatal("forged init image accepted")
	}
	forged = injected.DeepCopy()
	forged.Spec.Volumes = nil
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
		t.Fatal("missing Downward API config volume accepted")
	}
}

func TestDefaultGatewayUsesOperatorNamespace(t *testing.T) {
	namespace, gateway := fixture()
	gateway.(*v1alpha1.EgressGateway).Namespace = "egress-operator"
	h := setup(t, namespace, gateway)
	h.Namespace = "egress-operator"
	pod := optedPod()
	injected := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &injected, nil)); !r.Allowed {
		t.Fatalf("operator namespace default rejected: %+v", r.Result)
	}
}

func TestPolicyMatchesCompiled(t *testing.T) {
	ns, g := fixture()
	end := int32(444)
	p := &v1alpha1.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "apps"}, Spec: v1alpha1.EgressPolicySpec{GatewayRef: v1alpha1.GatewayReference{Name: "gateway"}, WorkloadSelector: metav1.LabelSelector{MatchLabels: map[string]string{GatewayLabel: "gateway"}}, Mode: "include", Rules: []v1alpha1.EgressRule{{CIDRs: []string{"198.51.100.0/24"}, Ports: []v1alpha1.EgressPort{{Protocol: "TCP", Port: 443, EndPort: &end}, {Protocol: "UDP", Port: 53}}}}, ExcludeCIDRs: []string{"203.0.113.0/24"}}}
	h := setup(t, ns, g, p)
	pod := optedPod()
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	var cfg datapath.ClientConfig
	if err := json.Unmarshal([]byte(out.Annotations[ConfigAnnotation]), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Identity.Policy != "policy" || cfg.Policy.Mode != "include" || len(cfg.Policy.Rules) != 1 || len(cfg.Policy.Rules[0].Ports) != 3 || len(cfg.Policy.ExcludeCIDRs) != 1 {
		t.Fatalf("compiled policy missing CIDRs, ports, exclusions: %+v", cfg.Policy)
	}
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !r.Allowed {
		t.Fatalf("compiled config not admitted: %+v", r.Result)
	}
	wrong := p.DeepCopy()
	wrong.Spec.GatewayRef.Name = "another-gateway"
	h = setup(t, ns, g, wrong)
	r := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
	if r.Allowed || !strings.Contains(r.Result.Message, "does not match selected gateway") {
		t.Fatalf("wrong policy gatewayRef accepted: %+v", r.Result)
	}
	p2 := p.DeepCopy()
	p2.Name = "policy2"
	h = setup(t, ns, g, p, p2)
	r = h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
	if r.Allowed || !strings.Contains(r.Result.Message, "multiple EgressPolicies") {
		t.Fatalf("multiple matches not explicit: %+v", r.Result)
	}
}
func TestExcludePolicyAndMetadata(t *testing.T) {
	ns, g := fixture()
	gateway := g.(*v1alpha1.EgressGateway)
	gateway.Spec.Exclusions.AllowCloudMetadata = true
	p := &v1alpha1.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "exclude", Namespace: "apps"}, Spec: v1alpha1.EgressPolicySpec{GatewayRef: v1alpha1.GatewayReference{Name: "gateway"}, WorkloadSelector: metav1.LabelSelector{MatchLabels: map[string]string{GatewayLabel: "gateway"}}, Mode: "exclude", Rules: []v1alpha1.EgressRule{{CIDRs: []string{"10.0.0.0/8"}}}}}
	h := setup(t, ns, gateway, p)
	pod := optedPod()
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	var cfg datapath.ClientConfig
	if err := json.Unmarshal([]byte(out.Annotations[ConfigAnnotation]), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowCloudMetadata || cfg.Policy.Mode != "exclude" || len(cfg.Policy.Rules) != 1 {
		t.Fatalf("exclude policy or metadata option missing: %+v", cfg)
	}
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !r.Allowed {
		t.Fatalf("exclude policy rejected: %+v", r.Result)
	}
	cfg.AllowCloudMetadata = false
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out.Annotations[ConfigAnnotation] = string(raw)
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); r.Allowed {
		t.Fatal("forged metadata allowance accepted")
	}
}
func TestPolicyValidationRejectsMalformedCompilation(t *testing.T) {
	h := setup(t)
	p := &v1alpha1.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "apps"}, Spec: v1alpha1.EgressPolicySpec{GatewayRef: v1alpha1.GatewayReference{Name: "gateway"}, Mode: "include", Rules: []v1alpha1.EgressRule{{CIDRs: []string{"not-a-cidr"}}}}}
	if r := h.Validate(context.Background(), req(t, "EgressPolicy", admissionv1.Create, p, nil)); r.Allowed || !strings.Contains(r.Result.Message, "invalid IPv4 CIDR") {
		t.Fatalf("invalid destination CIDR accepted: %+v", r.Result)
	}
	p.Spec.Rules = []v1alpha1.EgressRule{{Ports: []v1alpha1.EgressPort{{Protocol: "TCP", Port: 0}}}}
	if r := h.Validate(context.Background(), req(t, "EgressPolicy", admissionv1.Create, p, nil)); r.Allowed || !strings.Contains(r.Result.Message, "invalid port range") {
		t.Fatalf("invalid port accepted: %+v", r.Result)
	}
}

func TestValidatePodSelectionImmutableAtEveryPhase(t *testing.T) {
	h := setup(t)
	old := optedPod()
	old.Status.Phase = corev1.PodPending
	delete(old.Labels, GatewayLabel)
	newPod := old.DeepCopy()
	newPod.Labels[GatewayLabel] = "gateway"
	r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Update, newPod, old))
	if r.Allowed || !strings.Contains(r.Result.Message, "change the Deployment template and recreate the pod") {
		t.Fatalf("pending pod opted in without init: %+v", r.Result)
	}

	old = optedPod()
	old.Status.Phase = corev1.PodRunning
	newPod = old.DeepCopy()
	delete(newPod.Labels, GatewayLabel)
	r = h.Validate(context.Background(), req(t, "Pod", admissionv1.Update, newPod, old))
	if r.Allowed || !strings.Contains(r.Result.Message, "recreate the pod") {
		t.Fatalf("running gateway label removed: %+v", r.Result)
	}
	newPod = old.DeepCopy()
	newPod.Labels[GatewayNamespace] = "other"
	r = h.Validate(context.Background(), req(t, "Pod", admissionv1.Update, newPod, old))
	if r.Allowed {
		t.Fatal("running gateway namespace label changed")
	}
	newPod = old.DeepCopy()
	newPod.Annotations = map[string]string{GatewayNamespace: "other"}
	r = h.Validate(context.Background(), req(t, "Pod", admissionv1.Update, newPod, old))
	if r.Allowed {
		t.Fatal("running gateway namespace annotation changed")
	}
	newPod = old.DeepCopy()
	newPod.Annotations = map[string]string{ConfigAnnotation: `{"gatewayID":42,"endpoint":"10.9.9.9"}`}
	r = h.Validate(context.Background(), req(t, "Pod", admissionv1.Update, newPod, old))
	if r.Allowed {
		t.Fatal("client config annotation replaced after admission")
	}
	newPod = old.DeepCopy()
	newPod.Annotations = map[string]string{ReadyAnnotation: "true"}
	r = h.Validate(context.Background(), req(t, "Pod", admissionv1.Update, newPod, old))
	if !r.Allowed {
		t.Fatalf("controller datapath-ready annotation update rejected: %+v", r.Result)
	}
}
func TestPolicyOverlapAndGatewaySelector(t *testing.T) {
	ns, g := fixture()
	existing := &v1alpha1.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "existing", Namespace: "apps"}, Spec: v1alpha1.EgressPolicySpec{Mode: "include", WorkloadSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}}}}
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
