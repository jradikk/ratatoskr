package controller

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func gatewayWithProfiles(t *testing.T) (*GatewayReconciler, *api.EgressGateway) {
	t.Helper()
	r, gw := fixture(t)
	gw.Spec.Upstream.SecretRef = api.SecretReference{}
	gw.Spec.Replicas = 1
	gw.Spec.Upstream.Profiles = []api.UpstreamProfile{{Name: "berlin", SecretRef: api.SecretReference{Name: "berlin-key"}}, {Name: "oslo", SecretRef: api.SecretReference{Name: "oslo-key"}}}
	gw.Status.GatewayID = 17
	return r, gw
}
func TestGatewayProfileRenderedIsolationAndLegacy(t *testing.T) {
	r, gw := gatewayWithProfiles(t)
	objects, err := r.render(gw, []netip.Addr{netip.MustParseAddr("10.2.0.8")})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, obj := range objects {
		d, ok := obj.(*appsv1.Deployment)
		if !ok {
			continue
		}
		names = append(names, d.Name)
		if d.Labels[IdentityLabel] != gw.Name || d.Labels[ownerUIDLabel] != string(gw.UID) || d.Labels[profileLabel] == "" || *d.Spec.Replicas != 1 {
			t.Fatal("profile deployment identity/replicas invalid")
		}
		if d.Spec.Template.Spec.Volumes[1].Secret.SecretName != d.Labels[profileLabel]+"-key" {
			t.Fatal("profile leaked wrong Secret")
		}
		if d.Spec.Template.Spec.Volumes[0].ConfigMap.Name != gw.Name {
			t.Fatal("gateway config not shared")
		}
		if len(d.Spec.Template.Spec.Volumes[1].Secret.Items) != 0 {
			t.Fatal("profile Secret values must not be serialized into Pod template")
		}
	}
	if len(names) != 2 || names[0] != "edge-berlin" || names[1] != "edge-oslo" {
		t.Fatalf("profile Deployments %v", names)
	}
	cm := objects[0].(*corev1.ConfigMap)
	if len(cm.Data) != 1 || cm.Data["gateway.json"] == "" {
		t.Fatal("shared config missing")
	}
	svc := objects[1].(*corev1.Service)
	if svc.Spec.Selector[IdentityLabel] != gw.Name || svc.Spec.Selector[ownerUIDLabel] != string(gw.UID) {
		t.Fatal("common gateway selector broken")
	}
	gw.Spec.Upstream.Profiles = nil
	gw.Spec.Upstream.SecretRef = api.SecretReference{Name: "vpn"}
	legacy, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy) != 4 || legacy[2].(*appsv1.Deployment).Name != gw.Name {
		t.Fatal("legacy gateway changed")
	}
}
func TestGatewayProfileNamesRejectAmbiguity(t *testing.T) {
	r, gw := gatewayWithProfiles(t)
	_ = r
	for _, mutate := range []func(*api.EgressGateway){
		func(g *api.EgressGateway) { g.Spec.Upstream.SecretRef.Name = "vpn" },
		func(g *api.EgressGateway) { g.Spec.Replicas = 2 },
		func(g *api.EgressGateway) { g.Spec.Upstream.Profiles[1].Name = "berlin" },
		func(g *api.EgressGateway) { g.Spec.Upstream.Profiles[1].SecretRef.Name = "" },
		func(g *api.EgressGateway) { g.Name = "gateway-name-that-exceeds-fifty-chars-long-enough-for-profile" },
	} {
		bad := gw.DeepCopy()
		mutate(bad)
		if _, err := gatewayProfileNames(bad); err == nil {
			t.Fatal("ambiguous profile accepted")
		}
	}
}
func TestGatewayProfilePodOwnerAndRemovedDeployment(t *testing.T) {
	r, gw := gatewayWithProfiles(t)
	ctx := context.Background()
	desired, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, obj := range desired {
		if dep, ok := obj.(*appsv1.Deployment); ok {
			dep.UID = types.UID(dep.Name + "-uid")
			if err := r.Create(ctx, dep); err != nil {
				t.Fatal(err)
			}
		}
	}
	dep := desired[2].(*appsv1.Deployment)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "edge-berlin-rs", Namespace: gw.Namespace, UID: "rs-berlin", Labels: map[string]string{profileLabel: "berlin"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	if err := r.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "edge-berlin-pod", Namespace: gw.Namespace, Labels: map[string]string{IdentityLabel: gw.Name, ownerUIDLabel: string(gw.UID), profileLabel: "berlin"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}}
	if managed, err := r.managedGatewayPod(ctx, gw, pod); err != nil || !managed {
		t.Fatalf("profile Pod rejected: %v %v", managed, err)
	}
	changed := pod.DeepCopy()
	changed.OwnerReferences[0].UID = "wrong"
	if managed, _ := r.managedGatewayPod(ctx, gw, changed); managed {
		t.Fatal("forged ReplicaSet accepted")
	}
	for _, mutate := range []func(*corev1.Pod){
		func(p *corev1.Pod) { delete(p.Labels, profileLabel) },
		func(p *corev1.Pod) { p.Labels[profileLabel] = "oslo" },
	} {
		forged := pod.DeepCopy()
		mutate(forged)
		if managed, _ := r.managedGatewayPod(ctx, gw, forged); managed {
			t.Fatal("profile label forgery accepted")
		}
	}
	bad := gw.DeepCopy()
	bad.Spec.Upstream.Profiles = bad.Spec.Upstream.Profiles[1:]
	if managed, _ := r.managedGatewayPod(ctx, bad, pod); managed {
		t.Fatal("removed profile Pod accepted")
	}
	remaining, err := r.render(bad, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.removeStaleProfileDeployments(ctx, bad, remaining); err != nil {
		t.Fatal(err)
	}
	var removed appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKeyFromObject(dep), &removed); err == nil {
		t.Fatal("removed profile still serves")
	}
	var kept appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKeyFromObject(desired[3]), &kept); err != nil {
		t.Fatal("retained profile deleted")
	}
}

func TestGatewayMetricsOptInRendersScopedServiceAndIngressForProfiles(t *testing.T) {
	r, gw := gatewayWithProfiles(t)
	r.Options.GatewayMetricsEnabled = "true"
	r.Options.GatewayMetricsNamespaceSelector = `{"matchLabels":{"observability":"approved"}}`
	r.Options.GatewayMetricsPodSelector = `{"matchLabels":{"app":"prometheus"}}`
	objects, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	var metrics *corev1.Service
	var np *networkingv1.NetworkPolicy
	count := 0
	for _, obj := range objects {
		switch value := obj.(type) {
		case *appsv1.Deployment:
			count++
			gateway := value.Spec.Template.Spec.Containers[0]
			env := map[string]string{}
			for _, v := range gateway.Env {
				env[v.Name] = v.Value
			}
			if env["METRICS_ENABLED"] != "true" || env["METRICS_BIND_ADDRESS"] != "0.0.0.0:9902" {
				t.Fatal("enabled metrics not bound on profile gateway PodIP")
			}
			if gateway.Ports[len(gateway.Ports)-1].Name != "metrics" || gateway.Ports[len(gateway.Ports)-1].ContainerPort != 9902 {
				t.Fatal("profile metrics port missing")
			}
		case *corev1.Service:
			if value.Name == gw.Name+"-metrics" {
				metrics = value
			}
		case *networkingv1.NetworkPolicy:
			np = value
		}
	}
	if count != 2 || metrics == nil || np == nil {
		t.Fatal("profile gateway metrics resources missing")
	}
	if !metav1.IsControlledBy(metrics, gw) || metrics.Spec.Selector[IdentityLabel] != gw.Name || metrics.Spec.Selector[ownerUIDLabel] != string(gw.UID) || len(metrics.Spec.Ports) != 1 || metrics.Spec.Ports[0].Port != 9902 {
		t.Fatal("gateway metrics Service not scoped to owner")
	}
	rule := np.Spec.Ingress[len(np.Spec.Ingress)-1]
	if len(rule.From) != 1 || rule.Ports[0].Port.IntVal != 9902 || rule.From[0].NamespaceSelector.MatchLabels["observability"] != "approved" || rule.From[0].PodSelector.MatchLabels["app"] != "prometheus" {
		t.Fatalf("gateway metrics ingress not scoped: %+v", rule)
	}
	for _, raw := range []string{`{"matchLabels":{"secret":"PRIVATE"},"unknown":true}`, `not-json`, `{"matchExpressions":[{"key":"a","operator":"Bad"}]}`} {
		r.Options.GatewayMetricsNamespaceSelector = raw
		if _, err := r.render(gw, nil); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("invalid metrics selector accepted/leaked: %v", err)
		}
	}
	r.Options.GatewayMetricsEnabled = "false"
	r.Options.GatewayMetricsNamespaceSelector = "not-json"
	disabled, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, obj := range disabled {
		if svc, ok := obj.(*corev1.Service); ok && svc.Name == gw.Name+"-metrics" {
			t.Fatal("disabled metrics Service exposed")
		}
	}
}

func TestGatewayMetricsDisableRemovesOnlyOwnedService(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned", true: "foreign"}[foreign], func(t *testing.T) {
			r, gw := gatewayWithProfiles(t)
			ctx := context.Background()
			r.Options.GatewayMetricsEnabled = "true"
			r.Options.GatewayMetricsNamespaceSelector = `{"matchLabels":{"kubernetes.io/metadata.name":"monitoring"}}`
			r.Options.GatewayMetricsPodSelector = `{"matchLabels":{"app.kubernetes.io/name":"prometheus"}}`
			for _, name := range []string{"berlin-key", "oslo-key"} {
				if err := r.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace}, Data: map[string][]byte{"client.ovpn": []byte("private")}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Update(ctx, gw); err != nil {
				t.Fatal(err)
			}
			req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			metrics := &corev1.Service{}
			key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name + "-metrics"}
			if err := r.Get(ctx, key, metrics); err != nil {
				t.Fatal(err)
			}
			metrics.UID = types.UID("owned-metrics-uid")
			if foreign {
				metrics.OwnerReferences = nil
			}
			if err := r.Update(ctx, metrics); err != nil {
				t.Fatal(err)
			}
			r.Options.GatewayMetricsEnabled = "false"
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			remaining := &corev1.Service{}
			err := r.Get(ctx, key, remaining)
			if foreign && err != nil {
				t.Fatalf("foreign same-name metrics Service removed: %v", err)
			}
			if !foreign && err == nil {
				t.Fatal("disabled owned metrics Service still exists")
			}
			if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, &corev1.Service{}); err != nil {
				t.Fatalf("regular gateway Service removed: %v", err)
			}
			if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: "edge-berlin"}, &appsv1.Deployment{}); err != nil {
				t.Fatalf("gateway Deployment removed on metrics disable: %v", err)
			}
		})
	}
}

func TestGatewayMetricsDefaultAllowsAnySourceAndCustomSelectors(t *testing.T) {
	r, gw := gatewayWithProfiles(t)
	r.Options.GatewayMetricsEnabled = "true"
	for _, tc := range []struct {
		ns, pod string
		bounded bool
	}{
		{`{}`, `{}`, false},
		{`{}`, `{"matchLabels":{"app":"prometheus"}}`, true},
		{`{"matchLabels":{"team":"monitoring"}}`, `{}`, true},
		{`{"matchLabels":{"team":"monitoring"}}`, `{"matchLabels":{"app":"prometheus"}}`, true},
	} {
		r.Options.GatewayMetricsNamespaceSelector, r.Options.GatewayMetricsPodSelector = tc.ns, tc.pod
		objects, err := r.render(gw, nil)
		if err != nil {
			t.Fatal(err)
		}
		policy := objects[len(objects)-1].(*networkingv1.NetworkPolicy)
		rule := policy.Spec.Ingress[len(policy.Spec.Ingress)-1]
		if len(rule.Ports) != 1 || rule.Ports[0].Port.IntVal != 9902 || (len(rule.From) != 0) != tc.bounded {
			t.Fatalf("gateway metrics source scope mismatch: %+v", rule)
		}
		if tc.bounded && (rule.From[0].NamespaceSelector == nil || rule.From[0].PodSelector == nil) {
			t.Fatalf("partial selector must cover all namespaces or pods explicitly: %+v", rule)
		}
	}
	for _, tc := range []struct{ ns, pod string }{
		{"", `{"matchLabels":{"app":"prometheus"}}`},
		{`{"matchLabels":{"team":"monitoring"}}`, ""},
		{`{"matchLabels":{"team":"monitoring"}}`, `{"matchExpressions":[{"key":"app","operator":"Invalid","values":["prometheus"]}]}`},
	} {
		r.Options.GatewayMetricsNamespaceSelector, r.Options.GatewayMetricsPodSelector = tc.ns, tc.pod
		if _, err := r.render(gw, nil); err == nil {
			t.Fatal("missing/invalid metrics selector accepted")
		}
	}
}

func TestGatewayProfilesReconcileAllSecretsAndRetireRemovedProfile(t *testing.T) {
	r, gw := gatewayWithProfiles(t)
	ctx := context.Background()
	for _, name := range []string{"berlin-key", "oslo-key"} {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace}, Data: map[string][]byte{"client.ovpn": []byte("private-profile-" + name)}}
		if err := r.Create(ctx, secret); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Update(ctx, gw); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"edge-berlin", "edge-oslo"} {
		var dep appsv1.Deployment
		if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: name}, &dep); err != nil {
			t.Fatalf("profile %s missing: %v", name, err)
		}
		if dep.Spec.Template.Spec.Volumes[1].Secret.SecretName != strings.TrimPrefix(name, "edge-")+"-key" {
			t.Fatal("profile Secret mount mismatch")
		}
	}
	fresh := &api.EgressGateway{}
	if err := r.Get(ctx, req.NamespacedName, fresh); err != nil {
		t.Fatal(err)
	}
	fresh.Spec.Upstream.Profiles = fresh.Spec.Upstream.Profiles[:1]
	if err := r.Update(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var old appsv1.Deployment
	if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: "edge-oslo"}, &old); err == nil {
		t.Fatal("removed profile still running")
	}
	if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: "edge-berlin"}, &old); err != nil {
		t.Fatal("unchanged profile removed")
	}
}
