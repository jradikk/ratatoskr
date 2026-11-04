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
func TestAgentStateRequiresAuthenticatedAgentWriter(t *testing.T) {
	ns, gw := fixture()
	h := setup(t, ns, gw)
	h.Driver = "agent"
	p := optedPod()
	old := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, p, nil)), p)
	for _, key := range []string{prefix + "agent-config", prefix + "agent-hash", prefix + "agent-backend", prefix + "quarantine-reason", ReadyAnnotation} {
		t.Run(key, func(t *testing.T) {
			changed := old.DeepCopy()
			changed.Annotations[key] = "forged"
			r := req(t, "Pod", admissionv1.Update, changed, &old)
			r.UserInfo.Username = "ordinary-user"
			if h.Validate(context.Background(), r).Allowed {
				t.Fatal("ordinary Pod patch forged agent state")
			}
			r.UserInfo.Username = "system:serviceaccount:other:ratatoskr-agent"
			if h.Validate(context.Background(), r).Allowed {
				t.Fatal("other namespace agent accepted")
			}
			r.UserInfo.Username = "system:serviceaccount:system:ratatoskr-agent"
			if !h.Validate(context.Background(), r).Allowed {
				t.Fatal("authenticated operator agent rejected")
			}
		})
	}
	for _, key := range []string{prefix + "agent-config", prefix + "agent-hash", prefix + "agent-backend", prefix + "quarantine-reason"} {
		forged := old.DeepCopy()
		forged.Annotations[key] = "forged"
		if h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)).Allowed {
			t.Fatal("prepopulated agent state accepted on CREATE")
		}
	}
	unchanged := req(t, "Pod", admissionv1.Update, &old, &old)
	unchanged.UserInfo.Username = "kubelet"
	if !h.Validate(context.Background(), unchanged).Allowed {
		t.Fatal("status-style unchanged agent state rejected")
	}
}

func TestAgentWriterNamespaceIsIndependentOfGatewayDefault(t *testing.T) {
	ns, gw := fixture()
	h := setup(t, ns, gw)
	h.Driver = "agent"
	h.AgentNamespace = "operator-release"
	p := optedPod()
	old := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, p, nil)), p)
	updated := old.DeepCopy()
	updated.Annotations[ReadyAnnotation] = "true"
	r := req(t, "Pod", admissionv1.Update, updated, &old)
	r.UserInfo.Username = "system:serviceaccount:system:ratatoskr-agent"
	if h.Validate(context.Background(), r).Allowed {
		t.Fatal("gateway-default namespace must not authorize agent writer")
	}
	r.UserInfo.Username = "system:serviceaccount:operator-release:ratatoskr-agent"
	if !h.Validate(context.Background(), r).Allowed {
		t.Fatal("explicit deployment namespace agent rejected")
	}
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
func TestGeneratedNameInitFailsClosedAgentWaitsForAssignedUID(t *testing.T) {
	for _, encryption := range []string{"none", "wireguard"} {
		t.Run(encryption, func(t *testing.T) {
			namespace, object := fixture()
			gateway := object.(*v1alpha1.EgressGateway)
			gateway.Spec.Replicas = 3
			gateway.Spec.Encryption = encryption
			gateway.Status.Endpoints = []v1alpha1.GatewayEndpoint{{PodIP: "10.2.3.4", UpstreamHealthy: true}, {PodIP: "10.2.3.5", UpstreamHealthy: true}}
			pod := optedPod()
			pod.Name = ""
			pod.GenerateName = "client-"
			h := setup(t, namespace, gateway)
			response := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
			if response.Allowed || !strings.Contains(response.Result.Message, "init driver cannot stably select") {
				t.Fatalf("generated-name init admitted with unstable affinity: %+v", response.Result)
			}
			h.Driver = "agent"
			out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
			var cfg datapath.ClientConfig
			if err := json.Unmarshal([]byte(out.Annotations[ConfigAnnotation]), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Endpoint.IsValid() || cfg.GatewayPublicKey != "" || cfg.RegistrationCACert != "" || cfg.WireGuardPort != 0 || out.Annotations[ReadyAnnotation] != "pending" {
				t.Fatalf("agent generated-name Pod published endpoint before UID assignment: %+v", cfg)
			}
			if response = h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !response.Allowed {
				t.Fatalf("agent generated-name fail-closed Pod denied: %+v", response.Result)
			}
		})
	}
}

func TestGatewayIPv6EndpointDeniedAtAdmission(t *testing.T) {
	namespace, object := fixture()
	gateway := object.(*v1alpha1.EgressGateway)
	gateway.Status.Endpoints = []v1alpha1.GatewayEndpoint{{PodIP: "2001:db8::4", UpstreamHealthy: true}}
	h := setup(t, namespace, gateway)
	response := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, optedPod(), nil))
	if response.Allowed || !strings.Contains(response.Result.Message, "invalid PodIP") {
		t.Fatalf("IPv6-only healthy gateway endpoint admitted: %+v", response.Result)
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
			if init.SecurityContext == nil || init.SecurityContext.Capabilities == nil || !slices.Equal(init.SecurityContext.Capabilities.Add, tc.wantCaps) || !slices.Equal(init.SecurityContext.Capabilities.Drop, []corev1.Capability{"ALL"}) || len(init.VolumeMounts) != 1 || len(out.Spec.Volumes) != 1 {
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

func TestProgrammingInitRootOnlyUnderPodNonRootDefaults(t *testing.T) {
	namespace, gateway := fixture()
	h := setup(t, namespace, gateway)
	h.Driver = "init"
	pod := optedPod()
	nonRoot := true
	uid := int64(65532)
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: &nonRoot, RunAsUser: &uid}
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	init := out.Spec.InitContainers[0]
	sec := init.SecurityContext
	if sec == nil || sec.RunAsUser == nil || *sec.RunAsUser != 0 || sec.RunAsNonRoot == nil || *sec.RunAsNonRoot ||
		sec.Privileged == nil || *sec.Privileged || sec.AllowPrivilegeEscalation == nil || *sec.AllowPrivilegeEscalation ||
		sec.SeccompProfile == nil || sec.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault ||
		sec.Capabilities == nil || !slices.Equal(sec.Capabilities.Drop, []corev1.Capability{"ALL"}) || !slices.Equal(sec.Capabilities.Add, []corev1.Capability{"NET_ADMIN"}) {
		t.Fatalf("programming init does not explicitly override Pod-level nonroot safely: %+v", sec)
	}
	if out.Spec.SecurityContext == nil || out.Spec.SecurityContext.RunAsUser == nil || *out.Spec.SecurityContext.RunAsUser != uid ||
		out.Spec.SecurityContext.RunAsNonRoot == nil || !*out.Spec.SecurityContext.RunAsNonRoot || out.Spec.Containers[0].SecurityContext != nil {
		t.Fatal("programming init changed application Pod security")
	}
	if response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !response.Allowed {
		t.Fatalf("safe programming init denied: %+v", response.Result)
	}
	for _, tc := range []struct {
		name   string
		change func(*corev1.SecurityContext)
	}{
		{"nonroot UID", func(s *corev1.SecurityContext) { v := int64(65532); s.RunAsUser = &v }},
		{"missing root override", func(s *corev1.SecurityContext) { s.RunAsUser = nil }},
		{"forged nonroot", func(s *corev1.SecurityContext) { v := true; s.RunAsNonRoot = &v }},
		{"privileged", func(s *corev1.SecurityContext) { v := true; s.Privileged = &v }},
		{"allow privilege escalation", func(s *corev1.SecurityContext) { v := true; s.AllowPrivilegeEscalation = &v }},
		{"drop removed", func(s *corev1.SecurityContext) { s.Capabilities.Drop = nil }},
		{"extra capability", func(s *corev1.SecurityContext) { s.Capabilities.Add = append(s.Capabilities.Add, "SYS_ADMIN") }},
		{"seccomp unconfined", func(s *corev1.SecurityContext) { s.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forged := out.DeepCopy()
			tc.change(forged.Spec.InitContainers[0].SecurityContext)
			if response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); response.Allowed {
				t.Fatal("forged init security accepted")
			}
		})
	}
	agent := setup(t, namespace, gateway)
	agent.Driver = "agent"
	waitPod := mutatedPod(t, agent.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	wait := waitPod.Spec.InitContainers[0].SecurityContext
	if wait == nil || wait.RunAsUser == nil || *wait.RunAsUser == 0 || wait.Capabilities != nil && len(wait.Capabilities.Add) != 0 ||
		waitPod.Spec.SecurityContext.RunAsUser == nil || *waitPod.Spec.SecurityContext.RunAsUser != uid {
		t.Fatalf("agent wait-init or app privileges changed: %+v", wait)
	}
}

func TestInitGatewayAffinityStickyAcrossReorderAndFailover(t *testing.T) {
	namespace, object := fixture()
	gateway := object.(*v1alpha1.EgressGateway)
	gateway.Spec.Replicas = 3
	gateway.Status.Endpoints = []v1alpha1.GatewayEndpoint{
		{PodIP: "10.2.3.4", UpstreamHealthy: true},
		{PodIP: "10.2.3.5", UpstreamHealthy: true},
		{PodIP: "10.2.3.6", UpstreamHealthy: true},
	}
	h := setup(t, namespace, gateway)
	h.Driver = "init"
	pod := optedPod() // UID is empty at CREATE admission; use namespace/name.
	first := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	var initial datapath.ClientConfig
	if err := json.Unmarshal([]byte(first.Annotations[ConfigAnnotation]), &initial); err != nil {
		t.Fatal(err)
	}
	if !initial.Endpoint.IsValid() {
		t.Fatal("healthy gateway endpoint not selected")
	}
	gateway.Status.Endpoints[0], gateway.Status.Endpoints[2] = gateway.Status.Endpoints[2], gateway.Status.Endpoints[0]
	h = setup(t, namespace, gateway)
	reordered := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	var second datapath.ClientConfig
	if err := json.Unmarshal([]byte(reordered.Annotations[ConfigAnnotation]), &second); err != nil {
		t.Fatal(err)
	}
	if second.Endpoint != initial.Endpoint {
		t.Fatalf("endpoint list order changed sticky selection %s -> %s", initial.Endpoint, second.Endpoint)
	}
	if response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &reordered, nil)); !response.Allowed {
		t.Fatalf("sticky config rejected: %+v", response.Result)
	}
	for i := range gateway.Status.Endpoints {
		if gateway.Status.Endpoints[i].PodIP == initial.Endpoint.String() {
			gateway.Status.Endpoints[i].UpstreamHealthy = false
		}
	}
	h = setup(t, namespace, gateway)
	failedOver := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	var third datapath.ClientConfig
	if err := json.Unmarshal([]byte(failedOver.Annotations[ConfigAnnotation]), &third); err != nil {
		t.Fatal(err)
	}
	if !third.Endpoint.IsValid() || third.Endpoint == initial.Endpoint {
		t.Fatalf("failed endpoint still selected: %s", third.Endpoint)
	}
	if response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &failedOver, nil)); !response.Allowed {
		t.Fatalf("failover config rejected: %+v", response.Result)
	}
	gateway.Status.Endpoints = nil
	h = setup(t, namespace, gateway)
	closed := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	var missing datapath.ClientConfig
	if err := json.Unmarshal([]byte(closed.Annotations[ConfigAnnotation]), &missing); err != nil {
		t.Fatal(err)
	}
	if missing.Endpoint.IsValid() {
		t.Fatalf("no healthy endpoint did not fail closed: %+v", missing)
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
