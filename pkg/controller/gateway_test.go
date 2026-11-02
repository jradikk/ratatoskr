package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func fixture(t *testing.T) (*GatewayReconciler, *api.EgressGateway) {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{api.AddToScheme, corev1.AddToScheme, appsv1.AddToScheme, discoveryv1.AddToScheme, networkingv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	gw := &api.EgressGateway{ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "operator", UID: "unique-gateway", Generation: 1}, Spec: api.EgressGatewaySpec{Upstream: api.UpstreamSpec{Type: "openvpn", SecretRef: api.SecretReference{Name: "vpn"}}}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps", Labels: map[string]string{"team": "red"}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "operator"}, Data: map[string][]byte{"client.ovpn": []byte("client\n")}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(gw, &corev1.Pod{}).WithObjects(gw, ns, secret).Build()
	return &GatewayReconciler{Client: c, Scheme: scheme, Options: Options{OperatorNamespace: "operator", GatewayImage: "gateway:local", OpenVPNImage: "openvpn:local", Datapath: "iproute", ServiceCIDRs: "10.43.0.0/16", PodCIDRs: "10.42.0.0/16"}}, gw
}
func TestManagedWireGuardPodIdentity(t *testing.T) {
	r, gw := fixture(t)
	ctx := context.Background()
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace, UID: "dep-uid", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(gw, api.SchemeGroupVersion.WithKind("EgressGateway"))}}}
	if err := r.Create(ctx, dep); err != nil {
		t.Fatal(err)
	}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "edge-rs", Namespace: gw.Namespace, UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	if err := r.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: gw.Namespace, UID: "pod-uid", Labels: map[string]string{IdentityLabel: gw.Name, ownerUIDLabel: string(gw.UID)}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}, Spec: corev1.PodSpec{ServiceAccountName: "ratatoskr-gateway"}}
	managed, err := r.managedGatewayPod(ctx, gw, p)
	if err != nil || !managed {
		t.Fatalf("owned Pod denied: %v %v", managed, err)
	}
	forged := p.DeepCopy()
	forged.OwnerReferences = nil
	if managed, err = r.managedGatewayPod(ctx, gw, forged); err != nil || managed {
		t.Fatalf("label-only Pod accepted: %v %v", managed, err)
	}
	forged = p.DeepCopy()
	forged.OwnerReferences[0].UID = "wrong-rs-uid"
	if managed, err = r.managedGatewayPod(ctx, gw, forged); err != nil || managed {
		t.Fatalf("wrong ReplicaSet UID accepted: %v %v", managed, err)
	}
}

func TestRenderSecurityAndPodIPContract(t *testing.T) {
	r, gw := fixture(t)
	gw.Status.GatewayID = 123
	ips := []netip.Addr{netip.MustParseAddr("10.3.2.4")}
	objs, err := r.render(gw, ips)
	if err != nil {
		t.Fatal(err)
	}
	cm := objs[0].(*corev1.ConfigMap)
	var cfg datapath.GatewayConfig
	if err := json.Unmarshal([]byte(cm.Data["gateway.json"]), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.PodIP.IsValid() || cfg.GatewayID != 123 || !reflect.DeepEqual(cfg.Clients, ips) {
		t.Fatalf("invalid gateway config: %+v", cfg)
	}
	service := objs[1].(*corev1.Service)
	if len(objs) != 4 {
		t.Fatalf("expected ingress policy: %d objects", len(objs))
	}
	if len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Protocol != corev1.ProtocolUDP || service.Spec.Ports[0].Port != 6081 {
		t.Fatalf("incorrect discovery Service: %+v", service.Spec)
	}
	dep := objs[2].(*appsv1.Deployment)
	tpl := dep.Spec.Template
	if tpl.Labels[GatewayLabel] != "" || tpl.Labels[IdentityLabel] != "edge" {
		t.Fatal("gateway pod selected as workload")
	}
	g, u := tpl.Spec.Containers[0], tpl.Spec.Containers[1]
	if !reflect.DeepEqual(g.Command, []string{"/ratatoskr", "-config", "/config/gateway.json"}) || g.Env[0].Name != "POD_IP" {
		t.Fatal("gateway command/downward IP incorrect")
	}
	uidEnv := 0
	for _, env := range g.Env {
		if env.Name == "POD_UID" {
			uidEnv++
			if env.ValueFrom == nil || env.ValueFrom.FieldRef == nil || env.ValueFrom.FieldRef.FieldPath != "metadata.uid" {
				t.Fatalf("gateway POD_UID must use Downward API: %+v", env)
			}
		}
	}
	if uidEnv != 1 {
		t.Fatalf("gateway must receive exactly one POD_UID env in plain mode: %d", uidEnv)
	}
	for _, m := range g.VolumeMounts {
		if m.Name == "upstream" {
			t.Fatal("gateway has secret mount")
		}
	}
	if u.VolumeMounts[0].Name != "upstream" || len(g.SecurityContext.Capabilities.Add) != 1 || len(u.SecurityContext.Capabilities.Add) != 2 {
		t.Fatal("capability or secret isolation incorrect")
	}
}
func TestOperatorOnlyUpstreamProbe(t *testing.T) {
	r, gw := fixture(t)
	gw.Status.GatewayID = 123
	objects, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if args := objects[2].(*appsv1.Deployment).Spec.Template.Spec.Containers[1].Args; len(args) != 0 {
		t.Fatalf("default plugin probe must remain unchanged: %v", args)
	}
	r.Options.GatewayUpstreamProbeURL = "http://198.19.0.1:8080/exit"
	objects, err = r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	pod := objects[2].(*appsv1.Deployment).Spec.Template.Spec
	if !reflect.DeepEqual(pod.Containers[1].Args, []string{"--probe-url", r.Options.GatewayUpstreamProbeURL}) {
		t.Fatalf("operator probe override missing from upstream: %v", pod.Containers[1].Args)
	}
	if len(pod.Containers[0].Args) != 0 || pod.Containers[0].Command[0] != "/ratatoskr" || len(pod.Containers[1].SecurityContext.Capabilities.Add) != 2 {
		t.Fatal("probe override must not change gateway privileges or command")
	}
	for _, endpoint := range []string{
		"https://example.invalid/exit", "http://user:pass@198.19.0.1/exit",
		"http://127.0.0.1/exit", "http://[::1]/exit", "http://0.0.0.0/exit",
		"http://224.0.0.1/exit", "file:///tmp/private", "http://198.19.0.1:0/exit",
		"http://198.19.0.1:65536/exit", "http://198.19.0.1:8080/exit?token=x",
		"http://198.19.0.1/exit#secret", " http://198.19.0.1/exit",
	} {
		r.Options.GatewayUpstreamProbeURL = endpoint
		if _, err := r.render(gw, nil); err == nil {
			t.Errorf("unsafe operator probe accepted: %q", endpoint)
		}
	}
}

func TestGatewayReplicaRenderingAndEndpointRollout(t *testing.T) {
	r, gw := fixture(t)
	gw.Spec.Replicas = 3
	gw.Status.GatewayID = 123
	objects, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	dep := objects[2].(*appsv1.Deployment)
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 3 {
		t.Fatalf("expected three replicas: %+v", dep.Spec.Replicas)
	}
	a := api.GatewayEndpoint{PodName: "a", PodIP: "10.3.0.1", UpstreamHealthy: true, WireguardPublicKey: "old", RegistrationCACert: "ca"}
	b := api.GatewayEndpoint{PodName: "b", PodIP: "10.3.0.2", UpstreamHealthy: true}
	if endpointRestartRequired([]api.GatewayEndpoint{a}, []api.GatewayEndpoint{a, b}, false) {
		t.Fatal("adding a healthy replica cannot invalidate a pinned client")
	}
	if !endpointRestartRequired([]api.GatewayEndpoint{a, b}, []api.GatewayEndpoint{a}, false) {
		t.Fatal("removing a healthy replica must warn for pinned init clients")
	}
	changed := a
	changed.WireguardPublicKey = "new"
	if !endpointRestartRequired([]api.GatewayEndpoint{a}, []api.GatewayEndpoint{changed}, true) || endpointRestartRequired([]api.GatewayEndpoint{a}, []api.GatewayEndpoint{changed}, false) {
		t.Fatal("only encrypted init clients require rollout on identity rotation")
	}
	gw.Spec.Replicas = 33
	if _, err := r.render(gw, nil); err == nil {
		t.Fatal("out-of-range replicas accepted")
	}
}

func TestEBPFGatewayRenderingAndWireGuardRefusal(t *testing.T) {
	r, gw := fixture(t)
	r.Options.Datapath = "ebpf"
	gw.Status.GatewayID = 123
	objects, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway := objects[2].(*appsv1.Deployment).Spec.Template.Spec.Containers[0]
	ebpfEnv := false
	for _, env := range gateway.Env {
		if env.Name == "DATAPATH" && env.Value == "ebpf" {
			ebpfEnv = true
		}
	}
	if !ebpfEnv {
		t.Fatalf("missing eBPF gateway mode: %+v", gateway.Env)
	}
	if !reflect.DeepEqual(gateway.SecurityContext.Capabilities.Add, []corev1.Capability{"NET_ADMIN", "BPF", "PERFMON"}) {
		t.Fatalf("gateway eBPF capability scope: %+v", gateway.SecurityContext.Capabilities)
	}
	gw.Spec.Encryption = "wireguard"
	if _, err := r.render(gw, nil); err == nil {
		t.Fatal("eBPF WireGuard must fail closed")
	}
}

func TestAgentReadinessIsNotOwnedByController(t *testing.T) {
	r, gw := fixture(t)
	r.Options.Driver = "agent"
	gw.Spec.AllowedNamespaces.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "red"}}
	ctx := context.Background()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "restricted", Namespace: "apps", UID: "pod-agent", Labels: map[string]string{GatewayLabel: gw.Name}, Annotations: map[string]string{datapathReadyAnnotation: "true"}}, Status: corev1.PodStatus{Phase: corev1.PodPending, PodIP: "10.3.2.4"}}
	if err := r.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := r.Status().Update(ctx, pod); err != nil {
		t.Fatal(err)
	}
	ips, err := r.selected(ctx, gw)
	if err != nil || len(ips) != 1 {
		t.Fatalf("agent pod not selected: %v %v", ips, err)
	}
	var observed corev1.Pod
	if err := r.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, &observed); err != nil {
		t.Fatal(err)
	}
	if observed.Annotations[datapathReadyAnnotation] != "true" {
		t.Fatal("controller overwrote agent readiness because wait-init has not exited")
	}
}

func TestNoNamespaceSelectorDeniesEveryPod(t *testing.T) {
	r, gw := fixture(t)
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "selected", Namespace: "apps", Labels: map[string]string{GatewayLabel: "edge"}}, Status: corev1.PodStatus{Phase: corev1.PodPending, PodIP: "10.3.2.4"}}
	if err := r.Create(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := r.Status().Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	ips, err := r.selected(context.Background(), gw)
	if err != nil || len(ips) != 0 {
		t.Fatalf("nil allowedNamespaces selector must deny all: %v %v", ips, err)
	}
}

func TestSelectionPendingNamespaceAndLabels(t *testing.T) {
	r, gw := fixture(t)
	gw.Spec.AllowedNamespaces.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "red"}}
	ctx := context.Background()
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "apps", UID: "pod-one", Labels: map[string]string{GatewayLabel: "edge"}}, Status: corev1.PodStatus{Phase: corev1.PodPending, PodIP: "10.3.2.4"}}
	if err := r.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := r.Status().Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	ips, err := r.selected(ctx, gw)
	if err != nil || len(ips) != 1 || ips[0].String() != "10.3.2.4" {
		t.Fatalf("Pending PodIP missing: %v %v", ips, err)
	}
	first := EndpointID(p)
	if first != EndpointID(p) || first == EndpointID(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "replacement"}}) {
		t.Fatal("unstable endpoint ID")
	}
	p.Labels[GatewayLabel] = "different"
	if err := r.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	ips, err = r.selected(ctx, gw)
	if err != nil || len(ips) != 0 {
		t.Fatalf("stale label selection: %v %v", ips, err)
	}
}
func TestReconcileAllocationAndUnsupported(t *testing.T) {
	r, gw := fixture(t)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "operator", Name: "edge"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		t.Fatal(err)
	}
	if gw.Status.GatewayID == 0 || gw.Status.GatewayID > 0xffffff {
		t.Fatalf("bad VNI %d", gw.Status.GatewayID)
	}
	id := gw.Status.GatewayID
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var dep appsv1.Deployment
	if err := r.Get(ctx, req.NamespacedName, &dep); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		t.Fatal(err)
	}
	if gw.Status.GatewayID != id || meta.IsStatusConditionTrue(gw.Status.Conditions, "Ready") {
		t.Fatalf("invalid unready status %+v", gw.Status)
	}
	// WireGuard encryption is supported; a still-unsupported value
	// must instead remove a previously rendered gateway deployment.
	gw.Spec.Replicas = 33
	if err := r.Update(ctx, gw); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(gw.Status.Conditions, "Unsupported") || gw.Status.Phase != "Unsupported" {
		t.Fatalf("unsupported mode accepted %+v", gw.Status)
	}
	if err := r.Get(ctx, req.NamespacedName, &dep); err == nil {
		t.Fatal("deployment left running in unsupported mode")
	}
}
func TestMissingClusterCIDRsFailsClosed(t *testing.T) {
	r, gw := fixture(t)
	r.Options.ServiceCIDRs = ""
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "operator", Name: "edge"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	} // allocate VNI
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		t.Fatal(err)
	}
	if meta.IsStatusConditionTrue(gw.Status.Conditions, "Ready") || gw.Status.Phase != "Pending" {
		t.Fatalf("gateway incorrectly ready with unknown ServiceCIDR: %+v", gw.Status)
	}
	if !meta.IsStatusConditionTrue(gw.Status.Conditions, "ExclusionDiscoveryFailed") {
		t.Fatalf("missing failure condition: %+v", gw.Status.Conditions)
	}
	var dep appsv1.Deployment
	if err := r.Get(ctx, req.NamespacedName, &dep); err == nil {
		t.Fatal("forwarding deployment created with unknown cluster CIDRs")
	}
}

func TestGatewayAppliedConfigHashUsesExactRenderedBytes(t *testing.T) {
	r, gw := fixture(t)
	gw.Status.GatewayID = 123
	objects, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := expectedGatewayConfigHash(objects, gw)
	if err != nil {
		t.Fatal(err)
	}
	raw := objects[0].(*corev1.ConfigMap).Data["gateway.json"]
	sum := sha256.Sum256([]byte(raw))
	if hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash is not exact rendered bytes: %s", hash)
	}
	other := objects[0].(*corev1.ConfigMap).DeepCopy()
	other.Data["gateway.json"] = " " + raw
	altered, err := expectedGatewayConfigHash([]client.Object{other}, gw)
	if err != nil {
		t.Fatal(err)
	}
	if altered == hash {
		t.Fatal("whitespace byte change did not change hash")
	}
	other.OwnerReferences = nil
	if _, err := expectedGatewayConfigHash([]client.Object{other}, gw); err == nil {
		t.Fatal("unowned ConfigMap trusted")
	}
}
func TestGatewayAckDoesNotChangeUpstreamHealthDecision(t *testing.T) {
	// Membership acknowledgment is independent of upstream readiness and
	// measured MTU: stale ack must not starve clients of a healthy fallback.
	r, gw := fixture(t)
	gw.Status.GatewayID = 42
	ctx := context.Background()
	if err := r.Status().Update(ctx, gw); err != nil {
		t.Fatal(err)
	}
	createOwnedReplicaSet(t, r, gw)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gateway-1", Namespace: gw.Namespace, UID: "pod-uid", Labels: map[string]string{ownerUIDLabel: string(gw.UID), IdentityLabel: gw.Name}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "edge-rs", UID: "rs-uid"}}, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}, Status: corev1.PodStatus{PodIP: "10.42.0.5", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	if err := r.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := r.Status().Update(ctx, pod); err != nil {
		t.Fatal(err)
	}
	current := gatewayInfo{ExitIP: "198.51.100.9", Ready: true, PodMTU: 1500, GeneveMTU: 1450, UpstreamMTU: 1400, EffectiveMTU: 1400, MSS: 1360, PodUID: string(pod.UID)}
	r.HTTPClient = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		data, _ := json.Marshal(current)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: http.Header{}}, nil
	})}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}}
	fetch := func() api.GatewayEndpoint {
		t.Helper()
		if _, err := r.Reconcile(ctx, request); err != nil {
			t.Fatal(err)
		}
		var result api.EgressGateway
		if err := r.Get(ctx, request.NamespacedName, &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Status.Endpoints) != 1 || (current.PodUID == string(pod.UID) && (!result.Status.Endpoints[0].UpstreamHealthy || result.Status.MTU.EffectiveMTU != 1400)) || (current.PodUID != string(pod.UID) && (result.Status.Endpoints[0].UpstreamHealthy || result.Status.MTU.EffectiveMTU != 0)) {
			t.Fatalf("ack unexpectedly changed health or MTU: %+v", result.Status)
		}
		return result.Status.Endpoints[0]
	}
	ep := fetch()
	if ep.PodUID != string(pod.UID) || ep.AppliedClientConfigHash != "" {
		t.Fatalf("ready upstream with no ack not represented independently: %+v", ep)
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, &cm); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(cm.Data["gateway.json"]))
	want := hex.EncodeToString(sum[:])
	current.AppliedClientConfigHash = want
	ep = fetch()
	if ep.AppliedClientConfigHash != want {
		t.Fatalf("current applied hash not acknowledged: %+v", ep)
	}
	current.AppliedClientConfigHash = strings.Repeat("b", 64)
	ep = fetch()
	if ep.AppliedClientConfigHash != "" {
		t.Fatal("stale hash persisted")
	}
	current.AppliedClientConfigHash = want
	current.PodUID = "old-pod"
	ep = fetch()
	if ep.AppliedClientConfigHash != "" || ep.UpstreamHealthy {
		t.Fatalf("old Pod identity was trusted: %+v", ep)
	}
}

func TestGatewayAckRequiresMatchingPodUIDAndAppliedHash(t *testing.T) {
	hash := strings.Repeat("a", 64)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "current-pod"}}
	info := gatewayInfo{Ready: true, PodUID: "current-pod", AppliedClientConfigHash: hash}
	if !validGatewayAck(pod, info, hash) {
		t.Fatal("current Pod and desired applied hash not acknowledged")
	}
	info.AppliedClientConfigHash = strings.Repeat("b", 64)
	if validGatewayAck(pod, info, hash) {
		t.Fatal("stale config hash acknowledged")
	}
	info.AppliedClientConfigHash = hash
	info.PodUID = "old-pod"
	if validGatewayAck(pod, info, hash) {
		t.Fatal("old Pod UID acknowledged")
	}
	info.PodUID = ""
	if validGatewayAck(pod, info, hash) {
		t.Fatal("missing Pod UID acknowledged")
	}
	info.PodUID = "current-pod"
	info.AppliedClientConfigHash = ""
	if validGatewayAck(pod, info, hash) {
		t.Fatal("ready upstream without applied hash acknowledged")
	}
}

func TestGatewayIDCollision(t *testing.T) {
	r, gw := fixture(t)
	other := gw.DeepCopy()
	other.Name = "other"
	other.UID = "other-uid"
	other.ResourceVersion = ""
	other.Status.GatewayID = 54
	if err := r.Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	gw.Status.GatewayID = 54
	if _, err := r.allocateID(context.Background(), gw); err == nil {
		t.Fatal("collision accepted")
	}
}

func TestGatewayPodIPChangeRequiresClientRestart(t *testing.T) {
	r, gw := fixture(t)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "operator", Name: "edge"}}
	gw.Spec.AllowedNamespaces.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "red"}}
	if err := r.Update(ctx, gw); err != nil {
		t.Fatal(err)
	}
	gw.Status.GatewayID = 77
	gw.Status.Endpoints = []api.GatewayEndpoint{{PodName: "old", PodIP: "10.2.0.3", UpstreamHealthy: true}}
	if err := r.Status().Update(ctx, gw); err != nil {
		t.Fatal(err)
	}
	clientPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "apps", Labels: map[string]string{GatewayLabel: "edge"}}, Status: corev1.PodStatus{Phase: corev1.PodPending, PodIP: "10.3.0.9"}}
	if err := r.Create(ctx, clientPod); err != nil {
		t.Fatal(err)
	}
	if err := r.Status().Update(ctx, clientPod); err != nil {
		t.Fatal(err)
	}
	gatewayPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "new", Namespace: "operator", Labels: map[string]string{ownerUIDLabel: string(gw.UID), IdentityLabel: "edge"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "edge-rs", UID: "rs-uid"}}, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}, Status: corev1.PodStatus{PodIP: "10.2.0.4"}}
	createOwnedReplicaSet(t, r, gw)
	if err := r.Create(ctx, gatewayPod); err != nil {
		t.Fatal(err)
	}
	if err := r.Status().Update(ctx, gatewayPod); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(gw.Status.Conditions, "ClientRestartRequired") || gw.Status.ReadyReplicas != 0 {
		t.Fatalf("did not flag stale fixed remote: %+v", gw.Status)
	}
	if len(gw.Status.Endpoints) != 1 || gw.Status.Endpoints[0].PodIP != "10.2.0.4" {
		t.Fatalf("status endpoint is not real PodIP: %+v", gw.Status.Endpoints)
	}
}
func TestPolicyNoLongerBlocksGateway(t *testing.T) {
	r, gw := fixture(t)
	ctx := context.Background()
	gw.Status.GatewayID = 12
	if err := r.Status().Update(ctx, gw); err != nil {
		t.Fatal(err)
	}
	policy := &api.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "selective", Namespace: "apps"}, Spec: api.EgressPolicySpec{GatewayRef: api.GatewayReference{Name: "edge", Namespace: "operator"}}}
	if err := r.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "edge", Namespace: "operator"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		t.Fatal(err)
	}
	if meta.IsStatusConditionTrue(gw.Status.Conditions, "Unsupported") {
		t.Fatal("policy incorrectly marked gateway unsupported")
	}
	var dep appsv1.Deployment
	if err := r.Get(ctx, req.NamespacedName, &dep); err != nil {
		t.Fatalf("policy blocked gateway deployment: %v", err)
	}
}

func TestDatapathReadyRequiresSuccessfulNamedInit(t *testing.T) {
	r, _ := fixture(t)
	ctx := context.Background()
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "apps", Labels: map[string]string{GatewayLabel: "edge"}, Annotations: map[string]string{datapathReadyAnnotation: "pending"}}, Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: clientInitContainer}}}, Status: corev1.PodStatus{PodIP: "10.3.2.10"}}
	if err := r.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		if err := r.reconcilePodReadiness(ctx, p); err != nil {
			t.Fatal(err)
		}
		var stored corev1.Pod
		if err := r.Get(ctx, types.NamespacedName{Name: p.Name, Namespace: p.Namespace}, &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Annotations[datapathReadyAnnotation] != want {
			t.Fatalf("readiness %q; want %q", stored.Annotations[datapathReadyAnnotation], want)
		}
	}
	check("pending")
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: clientInitContainer, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1}}}}
	check("error")
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "unrelated", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}}
	check("pending")
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: clientInitContainer, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}}
	check("true")
	p.Spec.InitContainers = nil
	check("error")
}
func TestGatewayPodCannotBeMarkedWorkloadReady(t *testing.T) {
	r, gw := fixture(t)
	ctx := context.Background()
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gateway-pod", Namespace: "operator", Labels: map[string]string{GatewayLabel: "edge", IdentityLabel: "edge"}, Annotations: map[string]string{datapathReadyAnnotation: "pending"}}, Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: clientInitContainer}}}, Status: corev1.PodStatus{PodIP: "10.2.0.3", InitContainerStatuses: []corev1.ContainerStatus{{Name: clientInitContainer, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}}}}
	if err := r.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := r.Status().Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := r.selected(ctx, gw); err != nil {
		t.Fatal(err)
	}
	var stored corev1.Pod
	if err := r.Get(ctx, types.NamespacedName{Name: p.Name, Namespace: p.Namespace}, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Annotations[datapathReadyAnnotation] != "pending" {
		t.Fatal("gateway pod was marked as workload datapath ready")
	}
}

// createOwnedReplicaSet models the Deployment -> ReplicaSet chain Kubernetes
// creates before a gateway Pod can be trusted for endpoint publication.
func createOwnedReplicaSet(t *testing.T, r *GatewayReconciler, gw *api.EgressGateway) {
	t.Helper()
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace, UID: "dep-uid", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(gw, api.SchemeGroupVersion.WithKind("EgressGateway"))}}}
	if err := r.Create(context.Background(), dep); err != nil {
		t.Fatal(err)
	}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "edge-rs", Namespace: gw.Namespace, UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	if err := r.Create(context.Background(), rs); err != nil {
		t.Fatal(err)
	}
}
