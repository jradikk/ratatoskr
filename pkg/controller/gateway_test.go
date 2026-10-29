package controller

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
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
	for _, m := range g.VolumeMounts {
		if m.Name == "upstream" {
			t.Fatal("gateway has secret mount")
		}
	}
	if u.VolumeMounts[0].Name != "upstream" || len(g.SecurityContext.Capabilities.Add) != 1 || len(u.SecurityContext.Capabilities.Add) != 2 {
		t.Fatal("capability or secret isolation incorrect")
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
	if len(gateway.Env) < 2 || gateway.Env[1].Name != "DATAPATH" || gateway.Env[1].Value != "ebpf" {
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
	// WireGuard is supported beginning with M4; a still-unsupported value
	// must instead remove a previously rendered gateway deployment.
	gw.Spec.Replicas = 2
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
	gw.Status.Endpoints = []api.GatewayEndpoint{{PodName: "old", PodIP: "10.2.0.3"}}
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
	gatewayPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "new", Namespace: "operator", Labels: map[string]string{ownerUIDLabel: string(gw.UID), IdentityLabel: "edge"}}, Status: corev1.PodStatus{PodIP: "10.2.0.4"}}
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
		t.Fatal("M3 policy incorrectly marked gateway unsupported")
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
